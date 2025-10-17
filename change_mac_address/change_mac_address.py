#!/usr/bin/env python3
"""
Author: Vxiex11
Description: 
    A simple and secure MAC address changer for Linux systems using Python.
    It validates inputs, ensures root privileges, and uses subprocess safely 
    to avoid command injection vulnerabilities.

Usage Example:
    sudo python3 mac_changer.py -i eth0 -m AA:BB:CC:DD:EE:FF
"""

import argparse
import re
import subprocess
from termcolor import colored
import psutil
import os
import sys

def get_arguments():
    """
    Parse and return command-line arguments.
    
    Returns:
        argparse.Namespace: Contains parsed arguments (interface and MAC address).
    """
    parser = argparse.ArgumentParser(description="Change the MAC address of a network interface.")
    parser.add_argument(
        "-i", "--interface",
        dest="interface",
        required=True,
        help="Name of your network interface (e.g., eth0, wlan0)."
    )
    parser.add_argument(
        "-m", "--mac",
        dest="mac_address",
        required=True,
        help="New MAC address to assign (format: AA:BB:CC:DD:EE:FF)."
    )
    
    return parser.parse_args()


def check_root():
    """
    Verify that the script is executed with root privileges.
    Exits the program if not run as root.
    """
    if os.getuid() != 0:
        print(colored(
            "\n[!] Error: This script requires root privileges. "
            "Run it with 'sudo' or as the root user.", 
            "red"
        ))
        sys.exit(1)
    else:
        print(colored("[+] Root privileges verified. Proceeding...\n", "green"))


def get_interfaces():
    """
    Retrieve a list of available network interfaces on the system.
    
    Returns:
        list[str]: List of network interface names.
    """
    interfaces = psutil.net_if_addrs().keys()
    return list(interfaces)


def is_valid_input(interface, mac_address):
    """
    Validate the provided network interface and MAC address format.
    
    Args:
        interface (str): Network interface name.
        mac_address (str): Desired MAC address to assign.
    
    Returns:
        bool: True if both the interface and MAC address are valid, False otherwise.
    """
    current_interfaces = get_interfaces()
    valid_interface = interface in current_interfaces

    # MAC address format validation using regex
    is_valid_mac_address = re.match(r"^([A-Fa-f0-9]{2}[:-]){5}([A-Fa-f0-9]{2})$", mac_address)
    
    return valid_interface and is_valid_mac_address


def change_mac_address(interface, mac_address):
    """
    Change the MAC address of the specified network interface.
    
    Args:
        interface (str): Network interface name.
        mac_address (str): New MAC address to assign.
    """
    if is_valid_input(interface, mac_address):
        try:
            # Safely execute system commands (avoid shell=True)
            subprocess.run(["ifconfig", interface, "down"], check=True)
            subprocess.run(["ifconfig", interface, "hw", "ether", mac_address], check=True)
            subprocess.run(["ifconfig", interface, "up"], check=True)

            print(colored(f"[+] MAC address successfully changed for {interface} → {mac_address}", "green"))
        except subprocess.CalledProcessError:
            print(colored("[!] Failed to change the MAC address. Please check your permissions or interface name.", "red"))
    else:
        print(colored("[!] Invalid interface or MAC address format. Please verify your input.", "red"))


def main():
    """Main program logic."""
    check_root() # Always check if the user is root (require root permissions)
    args = get_arguments() # Get arguments by the user
    change_mac_address(args.interface, args.mac_address) # Finally -> Function to change the mac address


if __name__ == "__main__":
    main()
