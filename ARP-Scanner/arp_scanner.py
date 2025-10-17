#!/usr/bin/env python3
"""
ARP Scanner Script
Author: Vxiex11

Important:
- Keep running it with root privileges (sudo) because sending ARP frames
  typically requires elevated permissions.

Usage example:
    sudo python3 arp_scanner.py -t 192.168.1.0/24
"""

import scapy.all as scapy
import argparse
from termcolor import colored
import os
import sys
import ipaddress

def get_arguments():
    """
    Parse and return the command-line argument for the target.

    Returns:
        str: The target string provided by the user (e.g., "192.168.1.1/24").
    """
    parser = argparse.ArgumentParser(description = "ARP Scanner")
    parser.add_argument(
            "-t", "--target",
            required = True,
            dest = "target",
            help = "Host / IP Range to scan (E.g, 192.168.1.1/24)"
    )
    args = parser.parse_args()
    return args.target

def verify_ip(ip_str):
    """
    Verify whether the provided string is a valid IPv4 address or network.

    Uses the ipaddress module with strict=False so both single IPs and
    CIDR networks are accepted.

    Args:
        ip_str (str): IP address or network string to validate.

    Returns:
        bool: True if ip_str is a valid IPv4 address/network, False otherwise.
    """
    try:
        ipaddress.ip_network(ip_str, strict = False)  # Validate a unique address or ranges
        return True
    except ValueError:
        return False

def scan(ip):
    """
    Perform an ARP scan for the provided IP or network.

    This function:
      - Validates the input IP/network.
      - Builds an ARP request and Ethernet broadcast frame.
      - Sends the packet using scapy.srp and collects responses.
      - Formats and prints any active hosts found (IP + MAC).

    Args:
        ip (str): Target IP or network string.

    Exits:
        On invalid input (prints error and exits with sys.exit(1)).
    """
    # Validate the IP/network string; exit on invalid input
    if not verify_ip(ip):
        print(colored(f"[!] Error: Invalid IP Address", 'red'))
        sys.exit(1)

    # Build ARP request (pdst) and an Ethernet broadcast frame (dst = ff:ff:ff:ff:ff:ff)
    arp_packet = scapy.ARP(pdst = ip)
    broadcast_packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")  # Send to all devices on the link

    # Stack Ethernet + ARP so the frame is a broadcast ARP request
    arp_packet = broadcast_packet / arp_packet  # The '/' operator joins layers in Scapy

    # Send the packet and receive responses. srp = send and receive packets at layer 2
    # verbose=False suppresses Scapy output; timeout=1 waits 1 second for replies
    answered_list, unanswered = scapy.srp(arp_packet, verbose = False, timeout = 1)
    # answered_list is a list of (sent, received) tuples

    results_list = []  # Will store dictionaries of {"ip": <ip>, "mac": <mac>}
    for sent, received in answered_list:
        # received.psrc -> source IP from reply; received.hwsrc -> source MAC from reply
        results_list.append({"ip": received.psrc, "mac": received.hwsrc})

    # Print the results in a formatted table if any hosts replied
    if results_list:
        print(colored("-" * 44, 'blue'))
        print(colored("IP\t\t\tMAC Address", 'cyan'))
        print(colored("-" * 44, 'blue'))
        for client in results_list:
            print(f"{client['ip']}\t\t{client['mac']}")
        print(colored("-" * 44, 'blue'))
    else:
        # No replies received — either no active hosts or ARP replies blocked
        print(colored("\n[!] There are not activate hosts", 'yellow'))

def check_root():
    """
    Ensure the script is running with root privileges.

    Many Scapy operations (sending raw Ethernet frames) require elevated
    privileges. If the current UID is not 0, print an error and exit.
    """
    if os.getuid() != 0:
        print(colored("\n[!] Error: This script requires root privileges. "
            "Run it with 'sudo' or as the root user.", 
            "red"
        ))
        sys.exit(1)
    else:
        print(colored("[+] Root privileges verified. Proceeding...\n", "green"))

def main():
    """
    Main entry point:
      - Check for root privileges.
      - Parse arguments to get the target.
      - Execute the ARP scan using scan().
    """
    check_root()
    target = get_arguments()
    scan(target)


if __name__ == '__main__':
    # Print a newline for cleaner CLI output and run main
    print("")
    main()
