import json
import argparse
import socket
from termcolor import colored
from collections import defaultdict

class c:
    head = '\033[95m'
    ok_b = '\033[94m'
    ok_cy = '\033[96m'
    g = '\033[92m'
    warn = '\033[93m'
    fail = '\033[91m'
    reset = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

# Dictionary to store ASN data
asn_data = {}

# Defaultdict to store subdomains associated with each ASN
show_data = defaultdict(list)

# Dictionary to store hostname-to-IP mapping
hostname_to_ip = {}

def parse_arguments():
    parser = argparse.ArgumentParser(description="Summarize ASN-related data from a JSON file.")
    parser.add_argument("file_path", help="Path to the JSON file containing the data")
    parser.add_argument("hostname_file", help="Path to the JSON file containing hostname-to-IP mappings")
    return parser.parse_args()

def reverse_dns_lookup(ip):
    try:
        host_name, _, _ = socket.gethostbyaddr(ip)
        return host_name
    except (socket.herror, socket.gaierror):
        return "N/A"

def main():
    args = parse_arguments()

    # Read data from the JSON file
    with open(args.file_path, "r") as file:
        json_data = json.load(file)

    # Read hostname-to-IP mapping data from the second JSON file
    with open(args.hostname_file, "r") as hostfile:
        hostname_data = json.load(hostfile)

    # Build a mapping of IP ranges to hostnames
    for entry in hostname_data:
        host = entry.get("host")
        ips = entry.get("a")
        if host and ips:
            for ip in ips:
                hostname_to_ip[ip] = host

    # Iterate through the JSON data
    for item in json_data["TARGET"]:
        ip = item["input"]
        asn_number = item["as_number"]
        asn_name = item["as_name"]
        as_country = item["as_country"]
        as_range = item["as_range"]

        # Update ASN data if a new record is found with the same ASN number
        if asn_number not in asn_data:
            asn_data[asn_number] = {
                "as_name": asn_name,
                "as_country": as_country,
                "as_range": [],
                "total_ips": 0,
            }

        # Add unique CIDR ranges to the ASN data
        for cidr in as_range:
            if cidr not in asn_data[asn_number]["as_range"]:
                asn_data[asn_number]["as_range"].append(cidr)

        # Check if the IP is in hostname-to-IP mapping
        if ip in hostname_to_ip:
            hostname = hostname_to_ip[ip]
            show_data[asn_number].append((ip, hostname))
            asn_data[asn_number]["total_ips"] += 1
        else:
            # Perform reverse DNS lookup and add FQDN to the show_data dictionary
            fqdn = reverse_dns_lookup(ip)
            show_data[asn_number].append((ip, fqdn))
            asn_data[asn_number]["total_ips"] += 1

    # Print the summary with hostnames or FQDNs
    for asn, ip_hostname_pairs in show_data.items():
        
        print(f"{c.bold}{c.fail}ASN:{c.reset} {c.fail}{c.underline}{asn}{c.reset} {c.fail}- {asn_data[asn]['as_name']} ({asn_data[asn]['as_country']}){c.reset}")
        print(f"\t{c.bold}{c.warn}CIDR Ranges:{c.reset} {', '.join(asn_data[asn]['as_range'])}")
        print(f"\t{c.bold}{c.ok_b}Total IPs found:{c.reset} {asn_data[asn]['total_ips']}")
        for ip, hostname in ip_hostname_pairs:
            print(f"\t{c.bold}IP:{c.reset} {ip} - {c.bold}Hostname:{c.reset} {hostname}")
        print("\n")

if __name__ == "__main__":
    main()
