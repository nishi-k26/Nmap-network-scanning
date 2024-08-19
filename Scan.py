#!/usr/bin/python3

import nmap
from vulnerability_scans.ftp_scans import perform_ftp_scans
from vulnerability_scans.http_scans import perform_http_scans
from vulnerability_scans.ssh_scans import perform_ssh_scans
from vulnerability_scans.telnet_scans import perform_telnet_scans
from vulnerability_scans.smtp_scans import perform_smtp_scans
from vulnerability_scans.dns_scans import perform_dns_scans
from vulnerability_scans.https_scans import perform_https_scans
from vulnerabilities import (
    perform_ident_scans,
    perform_nfs_scans,
    perform_ntp_scans,
    perform_rdp_scans,
    perform_rpcbind_scans,
    perform_smb_scans,
    perform_snmp_scans,
    perform_pop3_scans,
    perform_msrpc_scans,
    perform_kerberos_scans,
    perform_netbios_scans,
    perform_imap_scans,
    perform_ldap_scans,
    perform_dhcp_scans
)

# Import the scanning functions

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
    
    if 23 in open_ports:
        perform_telnet_scans(target)
    
    if 25 in open_ports:
        perform_smtp_scans(target)
    
    if 53 in open_ports:
        perform_dns_scans(target)
    
    if 80 in open_ports:
        perform_http_scans(target)
    
    if 110 in open_ports:
        perform_pop3_scans(target)

    if 111 in open_ports:
        perform_rpcbind_scans(target)

    if 135 in open_ports:
        perform_msrpc_scans(target)

    if 139 in open_ports:
        perform_netbios_scans(target)

    if 143 in open_ports:
        perform_imap_scans(target)
    
    if 443 in open_ports:
        perform_https_scans(target)

    if 445 in open_ports:
        perform_smb_scans(target)

    if 161 in open_ports:
        perform_snmp_scans(target)
    
    if 389 in open_ports:
        perform_ldap_scans(target)

    if 67 in open_ports or 68 in open_ports:
        perform_dhcp_scans(target)

    # if 3306 in open_ports:
    #     perform_mysql_scans(target)
    
    if 3389 in open_ports:
        perform_rdp_scans(target)

    # if 5900 in open_ports:
    #     perform_vnc_scans(target)

    # if 8080 in open_ports:
    #     perform_http_proxy_scans(target)

    if 2049 in open_ports:
        perform_nfs_scans(target)

    if 123 in open_ports:
        perform_ntp_scans(target)

    if 113 in open_ports:
        perform_ident_scans(target)
    
    if 88 in open_ports:
        perform_kerberos_scans(target)
    
    # if 513 in open_ports:
    #     perform_rlogin_scans(target)
    
    # if 5432 in open_ports:
    #     perform_postgresql_scans(target)

    # if 6379 in open_ports:
    #     perform_redis_scans(target)
    
    print("--" * 45)
    print("Vulnerability scans completed.")

if __name__ == "__main__":
    main()
