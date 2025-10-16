# Host Discovery (ICMP) - 

A lightweight ICMP host discovery script that pings a single IP or a range in the last octet
(e.g., *192.168.1.1-100*) using concurrent threads.

---

## Features

- Simple and fast host discovery using **ping -c 1**.
- Concurrent scanning with **ThreadPoolExecutor**.
- Input validation for IPs and last-octet ranges.
- Colored terminal output using **termcolor**.
- Clean Ctrl+C handling (SIGINT).

---

## Usage
```bash
python3 host_discovery.py -t 192.168.1.1-30 -w 150
```

# Arguments:

-t / --target : Target IP or last-octet range (required). Examples:
192.168.1.5
192.168.1.1-50
-w / --workers : Number of concurrent workers (default 100)

# Example: 
```bash
python3 host_discovery.py -t 10.0.0.1-254 -w 200
```

# Behavior & Notes

Each host is pinged once (ping -c 1). Fast but may miss hosts behind firewall rules.
PING_TIMEOUT controls how long we wait for each ping subprocess; default is 1 second.
The script suppresses ping stdout and stderr for cleaner output.
Works on the majority of Linux distributions and macOS where ping -c is supported.
On some systems ping behavior and permission requirements differ (e.g., raw sockets).
If you need more reliable results, increase -w and/or PING_TIMEOUT or run multiple pings per host.


# [!] Security & Legal [!]

This tool is intended for educational and authorized network testing only.
Do NOT use it against networks or hosts you do not own or do not have explicit permission to test. The author is not responsible for misuse.
