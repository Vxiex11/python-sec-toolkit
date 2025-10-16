#!/usr/bin/env python3

import argparse
from termcolor import colored
import subprocess
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

def def_handler(sig, frame):
    print(colored(f"[!] Leaving the program...", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description = "Tool to find activate hosts in a network (ICMP)")
    parser.add_argument(
            "-t",
            "--target",
            dest = "target",
            required = True,
            help = "Host or network range to scan"
    )
    parser.add_argument(
            "-w",
            "--workers",
            dest = "max_workers",
            type = int,
            default = 100,
            help = "Numbers of concurrent workers (default: 100)"
    )
    args = parser.parse_args()
    
    return args.target, args.max_workers

def parse_target(target_str):

    # Example -> 192.168.1.1-100

    target_str_splitted = target_str.split('.') # -> ["192", "168", "1", "1-100"]

    if len(target_str_splitted) != 4:
        print(colored(f"\n[!] Invalid IP format (Eg: 192.168.1.1)", 'red'))
        sys.exit(1)

    first_three_octets = '.'.join(target_str_splitted[:3]) # -> "192.168.1"

    if "-" in target_str_splitted[3]:
        try:
            start, end = map(int, target_str_splitted[3].split('-'))
        except ValueError:
            print(colored(f"[!] Invalid range format", 'red'))
            sys.exit(1)

        if not (0 <= start <= 255 and 0 <= end <= 255) or start > end:
            print(colored(f"[!] Range must be betwwen 0-255 and start  < end", 'red'))
            sys.exit(1)

        return [f"{first_three_octets}.{i}" for i in range(int(start), int(end)+1)]
    else: # Only 1IP

        try:
            last_octect = int(target_str_splitted[3])
            if not (0 <= start <= 255):
                raise ValueError
        except ValueError:
            print(colored(f"[!] INvalid last octect in the IP", 'red'))
            sys.exit(1)

        return [target_str]

def host_discovery(target):
    
    try:
        ping = subprocess.run(
                ["ping", "-c", "1", target], 
                stderr = subprocess.DEVNULL, 
                stdout = subprocess.DEVNULL,
                timeout = 1
        ) # > /dev/null to not receive stdout or stderr

        if ping.returncode == 0: # If the ping is successfully
            print(colored(f"[+] IP: {target} is activate", 'green'))
    except subprocess.TimeoutExpired:
        pass

def implement_threads(targets, max_threads):

    with ThreadPoolExecutor(max_workers = max_threads) as executor:
        executor.map(host_discovery, targets)

def main():
    target_str, max_workers = get_arguments()
    targets = parse_target(target_str)
    implement_threads(targets, max_workers)


if __name__ == '__main__':
    print("")
    main()
