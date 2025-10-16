#!/usr/bin/env python3
"""
Author: Vxiex11
Description:
    Simple ICMP host discovery tool that pings single IPs or a range in the
    last octet (e.g., 192.168.1.1-100). Uses ThreadPoolExecutor to run
    concurrent pings and prints active hosts.

Usage (Example):
    python3 host_discovery.py -t 192.168.1.1-100 -w 200
"""

import argparse
from termcolor import colored
import subprocess
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# Timeout (in seconds) for each ping subprocess.run call
PING_TIMEOUT = 1


def def_handler(sig, frame):
    """
    Signal handler for Ctrl+C (SIGINT). Prints a message and exits cleanly.
    """
    print(colored("\n[!] Leaving the program...", "red"))
    sys.exit(1)


# Register Ctrl+C handler -> If the user decide to go out
signal.signal(signal.SIGINT, def_handler)


def get_arguments():
    """
    Parse command line arguments.

    Returns:
        tuple(str, int): (target_string, max_workers)
    """
    parser = argparse.ArgumentParser(description="Tool to find active hosts in a network (ICMP)")
    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="Host or network range to scan. Examples: 192.168.1.1 or 192.168.1.1-100"
    )
    parser.add_argument(
        "-w", "--workers",
        dest="max_workers",
        type=int,
        default=100,
        help="Number of concurrent workers (default: 100)"
    )
    args = parser.parse_args()

    return args.target, args.max_workers


def parse_target(target_str):
    """
    Parse the target string and return a list of IP addresses to scan.

    Acceptable formats:
      - Single IP: 192.168.1.10
      - Last-octet range: 192.168.1.1-50

    Args:
        target_str (str): Target string provided by the user.
    Returns:
        list[str]: List of IPv4 addresses as strings.

    Exits the program with an error message for invalid formats.
    """
    # Split by dots and validate
    parts = target_str.split('.')
    if len(parts) != 4:
        print(colored("\n[!] Invalid IP format (Eg: 192.168.1.1 or 192.168.1.1-100)", "red"))
        sys.exit(1)

    # Build the first three octets (e.g., "192.168.1")
    first_three = '.'.join(parts[:3])

    last_part = parts[3]

    # Range case: "1-100"
    if "-" in last_part:
        try:
            start_str, end_str = last_part.split('-', 1)
            start = int(start_str)
            end = int(end_str)
        except ValueError:
            print(colored("[!] Invalid range format (example: 1-100)", "red"))
            sys.exit(1)

        # Validate range values
        if not (0 <= start <= 255 and 0 <= end <= 255) or start > end:
            print(colored("[!] Range must be between 0-255 and start <= end", "red"))
            sys.exit(1)

        # Build list of valid IPv4 strings and double-check with ipaddress
        targets = []
        for i in range(start, end + 1):
            candidate = f"{first_three}.{i}"
            try:
                ipaddress.IPv4Address(candidate)
                targets.append(candidate)
            except ipaddress.AddressValueError:
                # Shouldn't happen thanks to previous validation, but keep it safe
                continue

        return targets

    else:
        # Single IP case (e.g., "192.168.1.5" or "192.168.1.05")
        try:
            last_octet = int(last_part)
        except ValueError:
            print(colored("[!] Invalid last octet in the IP", "red"))
            sys.exit(1)

        if not (0 <= last_octet <= 255):
            print(colored("[!] Last octet must be between 0 and 255", "red"))
            sys.exit(1)

        candidate = f"{first_three}.{last_octet}"
        # Validate full IP using ipaddress
        try:
            ipaddress.IPv4Address(candidate)
            return [candidate]
        except ipaddress.AddressValueError:
            print(colored("[!] Invalid IP address", "red"))
            sys.exit(1)


def host_discovery(target):
    """
    Ping a single target once. If the host responds, print that it's active.
    Args:
        target (str): IP address string to ping.
    """
    try:
        # Run ping once and suppress output
        # Using timeout for subprocess.run to avoid hanging threads
        ping = subprocess.run(
            ["ping", "-c", "1", target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT
        )

        if ping.returncode == 0:
            print(colored(f"[+] IP: {target} is active", "green"))
    except subprocess.TimeoutExpired:
        # Timeout: treat as host not responding
        pass
    except Exception as e:
        # Catch other unexpected exceptions for robustness
        print(colored(f"[!] Error pinging {target}: {e}", "red"))


def implement_threads(targets, max_threads):
    """
    Run host_discovery concurrently using ThreadPoolExecutor.
    Args:
        targets (list[str]): List of IP addresses.
        max_threads (int): Max concurrent workers.
    """
    if not targets:
        print(colored("[!] No targets to scan.", "red"))
        return

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # executor.map will consume the iterator and run tasks concurrently
        executor.map(host_discovery, targets)


def main():
    """
    Main entry point: parse args, build target list and run the scanner.
    """
    target_str, max_workers = get_arguments()
    targets = parse_target(target_str)
    implement_threads(targets, max_workers)


if __name__ == "__main__":
    # Print a small newline for cleaner CLI appearance
    print("")
    main()
