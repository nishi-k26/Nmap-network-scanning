#!/usr/bin/python3

import nmap
from vulnerability_scans import perform_ftp_scans, perform_ssh_scans  # Import the scanning functions

def scan_target(target):
    """Perform a basic scan to resolve the target hostname to IP address if necessary."""
    scanner = nmap.PortScanner()
    print(f"Scanning {target}...")
    scanner.scan(target)
    open_ports = []

    for host in scanner.all_hosts():
        print(f'Host: {host} ({scanner[host].hostname()})')
        print(f'State: {scanner[host].state()}')
        for proto in scanner[host].all_protocols():  # Iterate over each protocol
            print(f'Protocol: {proto}')  # Print the protocol name
            ports = list(scanner[host][proto].keys())  # Convert ports to a list
            print(f'Open ports: {ports}')  # Print the list of ports
            open_ports.extend(ports)  # Add ports to the open_ports list
            for port in ports:  # Iterate over each port
                print(f'Port: {port}\t State: {scanner[host][proto][port]["state"]}')  # Print port and its state
    
    return open_ports

def main():
    print("Welcome, this is a simple nmap vulnerability scanning program")
    print("--" * 45)

    target = input("Please enter the IP Address or DNS you want to scan: ")

    open_ports = scan_target(target)

    if 21 in open_ports:
        perform_ftp_scans(target)

    if 22 in open_ports:
        perform_ssh_scans(target)

    print("--" * 45)
    print("Vulnerability scans completed.")

if __name__ == "__main__":
    main()
