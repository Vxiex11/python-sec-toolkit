# ARP Scanner (Scapy) 

A compact ARP scanner that discovers active hosts on a local network using Scapy.
This repo contains the original script (unchanged) that accepts a single IP or a
CIDR range (e.g., `192.168.1.1` or `192.168.1.0/24`) and prints each discovered
host's IP and MAC address.

> **Important:** The script requires root privileges to send and receive ARP frames.
> Do **not** modify the original script unless you know what you are doing.


## Features

- Scans a single IP or an entire CIDR network (e.g., `192.168.1.0/24`).
- Uses **Scapy** to send ARP requests and capture replies.
- Clean, colored, human-friendly terminal output using `termcolor`.
- Validates the provided IP/network with Python's `ipaddress` module.
- Lightweight and easy to run on Linux/macOS systems with Scapy support.

# Usage

Run the script as root (example filenames assume arp_scanner.py):

```bash
sudo python3 arp_scanner.py -t 192.168.1.0/24
```

# Example to use

```bash
sudo python3 arp_scapy.py -t 192.168.100.1/24
```

Output will be (This is a ficticional example):

```bash
[+] Root privileges verified. Proceeding...
                                                                                                                                                                                                                                            
--------------------------------------------
IP                      MAC Address
--------------------------------------------
192.168.1.2           64:66:24:93:7f:eb
192.168.1.1           1a:05:77:4b:d3:8d
192.168.1.7           dr:9a:40:40:cb:e3
192.168.1.22          dr:c0:4d:b6:0d:37
192.168.1.31          dd:a2:37:65:48:a3
192.168.1.45          44:01:95:cd:a8:10
--------------------------------------------
```

# Behavior & Notes

Root required: Sending and receiving Ethernet frames (ARP) usually requires root privileges.
The script uses Scapy's srp() to send layer-2 (Ethernet) frames — it only works on local networks (not routed across subnets).
Hosts behind firewalls or switches that block ARP replies will not show up.
For large CIDR ranges, scanning might take time — consider increasing timeouts or adding parallelization if needed.

# [!] Security & Legal [!]

This tool is intended for authorized network testing and educational use only.
Do not scan networks or devices for which you do not have explicit permission. The
author is not responsible for misuse.
