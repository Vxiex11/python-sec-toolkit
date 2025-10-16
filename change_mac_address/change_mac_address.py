
#!/usr/bin/env python3

import argparse
import re
import subprocess
from termcolor import colored
import psutil
import os

def get_arguments():

    parser = argparse.ArgumentParser(description="Mac Changer")
    parser.add_argument(
        "-i",
        "--interface",
        dest="interface",
        required=True,
        help="Name of your interface",
    )
    parser.add_argument(
        "-m",
        "--mac",
        dest="mac_address",
        required=True,
        help="Mac address to change (Eg: AA:AA:AA:AA:AA:AA)"
    )
    
    return parser.parse_args()

def check_root():
    
    if os.getuid() != 0: # Verificate if the user is root
        print(colored(f"\n[!] Error: This script requires root privileges. Run it as sudo or as root", 'red'))
        exit()
    else:
        print(colored(f"\n[+] Root privileges verificated, working...\n\n", 'greem'))

def get_interfaces():
    interfaces = psutil.net_if_addrs().keys() # Library psutil allows us to view the user's network interfaces
    return list(interfaces)

def is_valid_input(interface, mac_address):

    # Valid case to the input
    current_interfaces = get_interfaces()
    if interface in current_interfaces:
        valid_interface = True
    else:
        valid_interface = False

    is_valid_mac_address = re.match(r'^([a-fA-Z0-9]{2}[:-]){5}([0-9A-Fa-z]{2})$', mac_address) # Regex/Patern to valid mac_address
    
    return valid_interface and is_valid_mac_address

def change_mac_address(interface, mac_address):

    if is_valid_input(interface, mac_address):
      # Secure way to execute commands
      subprocess.run(["ifconfig", interface, "down"]) # Subprocess for restrict command line ([!] Prevent Injection Attacks [!]), disable the network interface
      subprocess.run(["ifconfig", interface, "hw", "ether", mac_address]) # Switch to the other mac adrress 
      subprocess.run(["ifconfig", interface, "up"])

      print(colored(f"[+] Mac address successfully changed", 'green'))
    else:
        print(colored(f"[!] Data introduced are not correct", 'red'))

def main():
    check_root()
    args = get_arguments()
    change_mac_address(args.interface, args.mac_address)

if __name__ == '__main__':
    main()
