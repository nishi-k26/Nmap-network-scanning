#!/usr/bin/python3

import nmap
import subprocess

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap vulnerability scanning program")
print("--" * 45)

target = input("Please enter the IP Address or DNS you want to scan: ")

# Perform a basic scan to resolve the target hostname to IP address if necessary
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

print("--" * 45)

# Define the scan commands for FTP
ftp_scans = {
    "ftp_banner_grabbing": ["nmap", "-sV", "--script=banner", "-p", "21", target],
    "ftp_anonymous_access": ["nmap", "-sV", "--script=ftp-anon", "-p", "21", target],
    "ftp_bounce_scan": ["nmap", "-sV", "-sC", "-p", "21", target],
    "ftp_brute_force": ["nmap", "--script=ftp-brute", "-p", "21", target],
}
# Define the scan commands for SSH
ssh_scans = {
    "ssh_banner_grabbing": ["nmap", "-sV", "--script=banner", "-p", "22", target],
    "ssh_weak_algos": ["nmap", "--script=ssh2-enum-algos", "-p", "22", target],
    "ssh_weak_ciphers": ["nmap", "--script=ssh2-enum-algos", "-p", "22", target],
    "ssh_weak_macs": ["nmap", "--script=ssh2-enum-algos", "-p", "22", target],
    "ssh_v1_support": ["nmap", "--script=sshv1", "-p", "22", "-n", target]
}
# Define the scan commands for Telnet
telnet_scans = {
    "telnet_version": ["nmap", "-sV", "--script=banner", "-p", "23", target],
    "telnet_brute_force": ["nmap", "-p", "23", "--script", "telnet-brute", "--script-args", "userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s", target],
    "telnet_ntlm_info": ["nmap", "-p", "23", "--script=telnet-ntlm-info", target],
    "telnet_encryption": ["nmap", "-p", "23", "--script=telnet-encryption", target]
}

# Define the scan commands for SMTP
smtp_scans = {
    "smtp_version": ["nmap", "-sV", "--script=banner", "-p", "25", target],
    "smtp_open_relay": ["nmap", "--script=smtp-open-relay", "--script-args", "smtp-open-relay.domain=<domain>,smtp-open-relay.ip=<address>", "-p", "25,465,587", target],
    "smtp_enum_users": ["nmap", "--script=smtp-enum-users", "--script-args", "smtp-enum-users.methods={EXPN,...}", "-p", "25,465,587", target],
    "smtp_commands": ["nmap", "--script=smtp-commands", "--script-args", "smtp-commands.domain=<domain>", "-pT:25,465,587", target],
    "smtp_brute_force": ["nmap", "-p", "25", "--script=smtp-brute", target]
}
# Define the scan commands for DNS
dns_scans = {
    "dns_bruteforce": ["nmap", "--script=dns-brute", "-p", "53", target],
    "dns_basic_info": ["nmap", "-sV", "--script=dns-info", "-p", "53", target],
    "dns_reverse_lookup": ["nmap", "-sV", "--script=dns-reverse-lookup", "-p", "53", target],
    "dns_srv_enum": ["nmap", "-sV", "--script=dns-srv-enum", "-p", "53", target],
    "dns_zone_transfer": ["nmap", "--script=dns-zone-transfer", "--script-args", "dns-zone-transfer.domain=example.com", "-p", "53", target],
    "dns_cache_snoop": ["nmap", "-sU", "-p", "53", "--script=dns-cache-snoop", target],
    "dns_check_zone": ["nmap", "-sn", "-Pn", "--script=dns-check-zone", "--script-args=dns-check-zone.domain=example.com", "-p", "53", target],
    "dns_recursion": ["nmap", "-Pn", "-sU", "-p", "53", "--script=dns-recursion", target],
}
# Define the HTTP scan commands
http_scans = {
    "http_trace_track": ["curl", "-v", "-X", "TRACE", f"{target}:80"],
    "apache_etag_header": ["curl", "-v", "-X", "GET", f"{target}:80"],
    "http_sys_rce": ["curl", "-v", f"{target}:80/", "-H", "Host: irrelevant", "-H", "Range: bytes=0-18446744073709551615"]
}
# Define the HTTPS scan commands
https_scans = {
    "ssl_cert_check": ["nmap", "-sV", "-p", "443", "--script=ssl-cert", target],
    "ssl_protocol_detection": ["nmap", "-sV", "--script=ssl-enum-ciphers", "-p", "443", target],
    "ssl_poodle_vulnerability": ["nmap", "-sV", "--version-light", "--script=ssl-poodle", "-p", "443", target],
    "ssl_heartbleed": ["nmap", "-p", "443", "--script=ssl-heartbleed", target],
    "ssl_dh_params": ["nmap", "--script=ssl-dh-params", target],
    "ssl_weak_rsa_keys": ["nmap", "-sV", "-p", "443", "--script=ssl-cert", target],
    "ssl_weak_hash_algo": ["nmap", "-sV", "-p", "443", "--script=ssl-cert", target],
    "ssl_cert_expiry": ["nmap", "-sV", "-p", "443", "--script=ssl-cert", target],
    "ssl_wrong_hostname": ["nmap", "-sV", "-p", "443", "--script=ssl-cert", target],
    "ssl_ccs_injection": ["nmap", "-p", "443", "--script=ssl-ccs-injection", target],
    "ssl_sweet32": ["nmap", "-sV", "--script=ssl-enum-ciphers", "-p", "443", target],
    "ssl_lucky13": ["nmap", "-sV", "--script=ssl-enum-ciphers", "-p", "443", target],
    "ssl_rc4": ["nmap", "-sV", "--script=ssl-enum-ciphers", "-p", "443", target]
}

# Define the commands for POP3 scans
pop3_scans = {
    "pop3_banner_grabbing_cmd": ["nmap", "-sV", "--script=banner", target],
    "pop3_brute_force_cmd": ["nmap", "-sV", "--script=pop3-brute", target]
}

# Define the commands for RPCBIND scans
rpcbind_scans = {
    "nfs_mount_discloser_cmd": ["nmap", "-sV", target],
    "rpc_information_discloser_cmd": ["rpcinfo", "-p", target]
}

# Define the commands for MSRPC scans
msrpc_scans = {
    "msrpc_enumeration_cmd": ["nmap", target, "--script=msrpc-enum"],
    "msrpc_null_authentication_cmd_1": ["nmap", "--script=smb-enum-sessions.nse", "-p445", target],
    "msrpc_null_authentication_cmd_2": ["sudo", "nmap", "-sU", "-sS", "--script=smb-enum-sessions.nse", "-p", "U:137,T:139", target],
    "msrpc_null_authentication_cmd_3": ["rpcclient", "--U", "<username>", target]
}

# Define the commands for NETBIOS scans
netbios_scans = {
    "netbios_enumeration_cmd_1": ["enum", "-UMNSPGLdc", "-u", "<username>", "-p", "<password>", "-f", "dictfile", target],
    "netbios_enumeration_cmd_2": ["net", "view", f"\\\\{target}"],
    "netbios_enumeration_cmd_3": ["sudo", "nmap", "-sU", "--script", "nbstat.nse", "-p137", target],
    "netbios_brute_force_cmd_1": ["nmap", "--script", "smb-brute.nse", "-p445", target],
    "netbios_brute_force_cmd_2": ["sudo", "nmap", "-sU", "-sS", "--script", "smb-brute.nse", "-p", "U:137,T:139", target],
    "netbios_broadcast_cmd": ["nmap", "--script=broadcast-netbios-master-browser"]
}

# Define the commands for IMAP scans
imap_scans = {
    "imap_capabilities_disclosed_cmd": ["nmap", "-sV", "-sC", target],
    "imap_ntlm_info_cmd": ["nmap", "-p", "143,993", "--script", "imap-ntlm-info", target],
    "imap_brute_force_cmd": ["nmap", "-p", "143,993", "--script", "imap-brute", target]
}

# Define the commands for SMB scans
smb_scans = {
    "smb_version_cmd_1": ["use", "auxiliary/scanner/smb/smb_version"],
    "smb_version_cmd_2": ["nmap", "-sV", "--script=banner", target],
    "smb_null_session_auth_cmd_1": ["rpcclient", "-U", '""', target],
    "smb_null_session_auth_cmd_2": ["smbclient", "-L", target],
    "smb_null_session_auth_cmd_3": ["smbclient", f"//{target}/IPC$", "-N"],
    "smb_signing_required_cmd": ["nmap", "--script", "smb-security-mode", "-p445", target],
    "smb_signing_disabled_cmd": ["nmap", "--script", "smb-security-mode", "-p445", target],
    "smb_v1_vulnerabilities_cmd": ["nmap", "--script", "smb-protocols", target],
    "smb_eternalblue_cmd_1": ["nmap", "-p445", "--script", "smb-vuln-ms17-010", target],
    "smb_eternalblue_cmd_2": ["use", "exploit/windows/smb/ms17_010_eternalblue"]
}

# Define the commands for SNMP scans
snmp_scans = {
    "snmp_default_community_name_cmd": ["./snmpcheck-1.8.pl", "-t", target, "-c", "public"],
    "snmp_enumeration_cmd": ["use", "auxiliary/scanner/snmp/snmp_enum"],
    "snmp_mib_enumeration_cmd": ["nmap", "-sU", "-p 161", "--script=snmp-interfaces", target],
    "snmp_bruteforce_cmd": ["nmap", "-sU", "--script", "snmp-brute", target, "--script-args", "snmp-brute.communitiesdb=<wordlist>"]
}

# Define the commands for LDAP scans
ldap_scans = {
    "ldap_enumeration_cmd": ["nmap", "-p 389", "--script=ldap-rootdse", target],
    "ldap_brute_force_cmd": ["nmap", "-p 389", "--script=ldap-brute", "--script-args", 'ldap.base="cn=users,dc=cqure,dc=net"', target],
    "ldap_null_base_search_cmd": ["ldapsearch", "-h", target, "-x", "-s", "base"]
}

# Define the commands for DHCP scans
dhcp_scans = {
    "dhcp_discover_request_cmd": ["nmap", "-sU", "-p 67", "--script=dhcp-discover", target],
    "dhcp_starvation_attack_cmd": ["dhcp_starve.py", target]
}

# Define the commands for MySQL scans
mysql_scans = {
    "mysql_version_cmd": ["use", "auxiliary/scanner/mysql/mysql_version"],
    "mysql_hashdump_cmd": ["use", "auxiliary/scanner/mysql/mysql_hashdump"],
    "mysql_brute_force_cmd_1": ["use", "auxiliary/scanner/mysql/mysql_login"],
    "mysql_brute_force_cmd_2": ["nmap", "--script=mysql-brute", target]
}




# Perform FTP scans if port 21 is open
if 21 in open_ports:
    print("Starting FTP vulnerability scans...")
    subprocess.run(ftp_scans["ftp_banner_grabbing"])
    subprocess.run(ftp_scans["ftp_anonymous_access"])
    subprocess.run(ftp_scans["ftp_bounce_scan"])
    subprocess.run(ftp_scans["ftp_brute_force"])
    print("Completed FTP vulnerability scans.")

# Perform SSH scans if port 22 is open
if 22 in open_ports:
    print("Starting SSH vulnerability scans...")
    subprocess.run(ssh_scans["ssh_banner_grabbing"])
    subprocess.run(ssh_scans["ssh_weak_algos"])
    subprocess.run(ssh_scans["ssh_weak_ciphers"])
    subprocess.run(ssh_scans["ssh_weak_macs"])
    subprocess.run(ssh_scans["ssh_v1_support"])
    print("Completed SSH vulnerability scans.")

# Perform Telnet scans if port 23 is open
if 23 in open_ports:
    print("Starting Telnet vulnerability scans...")
    subprocess.run(telnet_scans["telnet_version"])
    subprocess.run(telnet_scans["telnet_brute_force"])
    subprocess.run(telnet_scans["telnet_ntlm_info"])
    subprocess.run(telnet_scans["telnet_encryption"])
    print("Completed Telnet vulnerability scans.")

# Perform SMTP scans if port 25 is open
if 25 in open_ports:
    print("Starting SMTP vulnerability scans...")
    subprocess.run(smtp_scans["smtp_version"])
    subprocess.run(smtp_scans["smtp_open_relay"])
    subprocess.run(smtp_scans["smtp_enum_users"])
    subprocess.run(smtp_scans["smtp_commands"])
    subprocess.run(smtp_scans["smtp_brute_force"])
    print("Completed SMTP vulnerability scans.")

# Perform DNS scans if port 53 is open
if 53 in open_ports:
    print("Starting DNS vulnerability scans...")
    subprocess.run(dns_scans["dns_bruteforce"])
    subprocess.run(dns_scans["dns_basic_info"])
    subprocess.run(dns_scans["dns_reverse_lookup"])
    subprocess.run(dns_scans["dns_srv_enum"])
    subprocess.run(dns_scans["dns_zone_transfer"])
    subprocess.run(dns_scans["dns_cache_snoop"])
    subprocess.run(dns_scans["dns_check_zone"])
    subprocess.run(dns_scans["dns_recursion"])
    print("Completed DNS vulnerability scans.")

# Perform HTTP scans if port 80 is open
if 80 in open_ports:
    print("Starting HTTP vulnerability scans...")
    subprocess.run(http_scans["http_trace_track"])
    subprocess.run(http_scans["apache_etag_header"])
    subprocess.run(http_scans["http_sys_rce"])
    print("Completed HTTP vulnerability scans.")

 # Perform HTTPS scans if port 443 is open
if 443 in open_ports:
    print("Starting HTTPS vulnerability scans...")
    subprocess.run(https_scans["ssl_cert_check"])
    subprocess.run(https_scans["ssl_protocol_detection"])
    subprocess.run(https_scans["ssl_poodle_vulnerability"])
    subprocess.run(https_scans["ssl_heartbleed"])
    subprocess.run(https_scans["ssl_dh_params"])
    subprocess.run(http_scans["ssl_weak_rsa_keys"])
    subprocess.run(https_scans["ssl_weak_hash_algo"])
    subprocess.run(https_scans["ssl_cert_expiry"])
    subprocess.run(https_scans["ssl_wrong_hostname"])
    subprocess.run(https_scans["ssl_ccs_injection"])
    subprocess.run(https_scans["ssl_sweet32"])
    subprocess.run(https_scans["ssl_lucky13"])
    subprocess.run(https_scans["ssl_rc4"])
    print("Completed HTTPS vulnerability scans.")

# Perform POP3 scans if port 110 is open
if 110 in open_ports:
    print("Starting POP3 vulnerability scans...")
    subprocess.run(pop3_scans["pop3_banner_grabbing_cmd"])
    subprocess.run(pop3_scans["pop3_brute_force_cmd"])
    print("Completed POP3 vulnerability scans.")

# Perform RPCBIND scans if port 111 is open
if 111 in open_ports:
    print("Starting RPCBIND vulnerability scans...")
    subprocess.run(rpcbind_scans["nfs_mount_discloser_cmd"])
    subprocess.run(rpcbind_scans["rpc_information_discloser_cmd"])
    print("Completed RPCBIND vulnerability scans.")

# Perform MSRPC scans if port 135 is open
if 135 in open_ports:
    print("Starting MSRPC vulnerability scans...")
    subprocess.run(msrpc_scans["msrpc_enumeration_cmd"])
    subprocess.run(msrpc_scans["msrpc_null_authentication_cmd_1"])
    subprocess.run(msrpc_scans["msrpc_null_authentication_cmd_2"])
    subprocess.run(msrpc_scans["msrpc_null_authentication_cmd_3"])
    print("Completed MSRPC vulnerability scans.")

# Perform NETBIOS scans if port 139 is open
if 139 in open_ports:
    print("Starting NETBIOS vulnerability scans...")
    subprocess.run(netbios_scans["netbios_enumeration_cmd_1"])
    subprocess.run(netbios_scans["netbios_enumeration_cmd_2"])
    subprocess.run(netbios_scans["netbios_enumeration_cmd_3"])
    subprocess.run(netbios_scans["netbios_brute_force_cmd_1"])
    subprocess.run(netbios_scans["netbios_brute_force_cmd_2"])
    subprocess.run(netbios_scans["netbios_broadcast_cmd"])
    print("Completed NETBIOS vulnerability scans.")

# Perform IMAP scans if port 143 is open
if 143 in open_ports:
    print("Starting IMAP vulnerability scans...")
    subprocess.run(imap_scans["imap_capabilities_disclosed_cmd"])
    subprocess.run(imap_scans["imap_ntlm_info_cmd"])
    subprocess.run(imap_scans["imap_brute_force_cmd"])
    print("Completed IMAP vulnerability scans.")

# Perform SMB scans if port 445 is open
if 445 in open_ports:
    print("Starting SMB vulnerability scans...")
    subprocess.run(smb_scans["smb_version_cmd_1"])
    subprocess.run(smb_scans["smb_version_cmd_2"])
    subprocess.run(smb_scans["smb_null_session_auth_cmd_1"])
    subprocess.run(smb_scans["smb_null_session_auth_cmd_2"])
    subprocess.run(smb_scans["smb_null_session_auth_cmd_3"])
    subprocess.run(smb_scans["smb_signing_required_cmd"])
    subprocess.run(smb_scans["smb_signing_disabled_cmd"])
    subprocess.run(smb_scans["smb_v1_vulnerabilities_cmd"])
    subprocess.run(smb_scans["smb_eternalblue_cmd_1"])
    subprocess.run(smb_scans["smb_eternalblue_cmd_2"])
    print("Completed SMB vulnerability scans.")

# Perform SNMP scans if port 161 is open
if 161 in open_ports:
    print("Starting SNMP vulnerability scans...")
    subprocess.run(snmp_scans["snmp_default_community_name_cmd"])
    subprocess.run(snmp_scans["snmp_enumeration_cmd"])
    subprocess.run(snmp_scans["snmp_mib_enumeration_cmd"])
    subprocess.run(snmp_scans["snmp_bruteforce_cmd"])
    print("Completed SNMP vulnerability scans.")

# Perform LDAP scans if port 389 is open
if 389 in open_ports:
    print("Starting LDAP vulnerability scans...")
    subprocess.run(ldap_scans["ldap_enumeration_cmd"])
    subprocess.run(ldap_scans["ldap_brute_force_cmd"])
    subprocess.run(ldap_scans["ldap_null_base_search_cmd"])
    print("Completed LDAP vulnerability scans.")

# Perform DHCP scans if ports 67 or 68 are open
if 67 in open_ports or 68 in open_ports:
    print("Starting DHCP vulnerability scans...")
    subprocess.run(dhcp_scans["dhcp_discover_request_cmd"])
    subprocess.run(dhcp_scans["dhcp_starvation_attack_cmd"])
    print("Completed DHCP vulnerability scans.")

# Perform MySQL scans if port 3306 is open
if 3306 in open_ports:
    print("Starting MySQL vulnerability scans...")
    subprocess.run(mysql_scans["mysql_version_cmd"])
    subprocess.run(mysql_scans["mysql_hashdump_cmd"])
    subprocess.run(mysql_scans["mysql_brute_force_cmd_1"])
    subprocess.run(mysql_scans["mysql_brute_force_cmd_2"])
    print("Completed MySQL vulnerability scans.")


print("--" * 45)
print("Vulnerability scans completed.")
