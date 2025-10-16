# Program to change mac address

A secure and lightweight Python tool to change your **MAC address** on Linux systems.

## Features

- Checks for **root privileges**
- Validates **network interface** and **MAC address format**
- Uses **subprocess** securely (prevents command injection)
- Displays colorful output with termcolor
- Lists system interfaces automatically via **psutil**

## Requirements

Make sure you have Python 3 installed and the following modules:

```bash
python3
```
You can then check whether you can import the psutil library
```bash
import psutil
```
If it does not contain any errors, you can import the library without any problems. If it contains errors, install it.
```bash
pip install psutil termcolor
```

You must run this script with root privileges:
```bash
sudo python3 mac_changer.py -i <interface> -m <new_mac>
```
Example output:
```bash
[+] Root privileges verified. Proceeding...
[+] MAC address successfully changed for eth0 → AA:BB:CC:DD:EE:FF
```

# Security Notes

This script uses **subprocess.run** without shell=True, making it safe against injection attacks.
Only works on Linux-based systems (tested on Ubuntu and Kali Linux).
Requires root access to modify network configurations.


# [!] IMPORTANT [!] Disclaimer

This tool is for educational and ethical testing purposes only.
Do not use it on networks or systems you do not own or have explicit permission to test.
