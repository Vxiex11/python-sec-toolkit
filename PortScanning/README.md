# TCP Port Scanner

A lightweight, well-documented TCP port scanner with optional HTTP HEAD probing and TLS certificate probing for port 443.
Designed for learning, red-team/blue-team lab work, and small authorized network reconnaissance tasks.

[!] Important: This tool is for educational and authorized testing only. Do not scan systems you do not own or do not have explicit permission to test. [!]

**Features**

1) Concurrent scanning using ThreadPoolExecutor
2) Optional HTTP HEAD probe for ports 80 / 8080
3) Optional TLS handshake probe for port 443 (extracts certificate CN)
4) Robust banner parsing (shows readable text or hex preview for binary data)
5) Clean Ctrl+C handling that closes open sockets
6) CLI flags for workers, timeout, and probe options
7) Clear, documented, and easy-to-read Python code

**How to use it**
[!] Important, In this example. I scan 30,000 ports, but I use 100 threads. You should consider your computer's specifications.
```bash
  python3 port_scanner_v2.py -t 192.168.100.1 -p 80-30000 --probe-https --workers 100 --timeout 1
```
Output (In my case):
```bash
[+] Port: 80 is open - HTTP/1.1 404 Not Found
[+] Port: 27998 is open
```

**CLI Options**

  1) -t, --target       Target to scan (IP or hostname) — required.
  2) -p, --port         Ports to scan (range, comma list, or single port) — required.
  3) --no-head          Do not send HTTP HEAD to ports 80/8080.
  4) --probe-https      Attempt TLS handshake on port 443 and extract cert CN.
  5) --workers N        Number of concurrent worker threads (default: 70).
  6) --timeout S        Socket timeout in seconds (default: 0.7).

If a banner is readable, you will see:
```bash
[+] Port: 80 is open - HTTP/1.1 200 OK
```
If the response contains non-printable bytes, you will see a hex preview:
```bash
[+] Port: 23 is open - <binary 64 bytes> hex=3f8a...
```
If no banner is returned:
```bash
[+] Port: 53 is open
```
