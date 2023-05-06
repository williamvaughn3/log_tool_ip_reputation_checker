#!/bin/python3.6
import json
import argparse
import os
import re
import yaml
import ipaddress
from ReputationChecker import *

DEFAULT_CONFIG_FILE = "config.yaml"

def get_log_files(file_path, dir_path):
    """Returns a list of log files to process."""
    if file_path:
        return [file_path]
    elif dir_path:
        log_files = []
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if file.endswith('.log'):
                    log_files.append(os.path.join(root, file))
        return log_files


def extract_ip_addresses(log_file):
    """Returns a set of unique IP addresses in the given log file."""
    with open(log_file, "r") as f:
        return set(match.group() for match in re.finditer(r"([0-9]{1,3}\.){3}[0-9]{1,3}", f.read()))


def print_ips(sorted_ips, output_file=None):
    """Prints the unique IP addresses to console and writes to output file if specified."""
    for ip in sorted_ips:
        print(ip)
        if output_file:
            with open(output_file, "a") as f:
                f.write(ip + "\n")

def check_valid(ip):
    if ip == '0.0.0.0':
        return False
    if ipaddress.ip_network(ip):
        addr = ipaddress.ip_address(ip)
        if addr.is_global and not addr.is_multicast:
            return addr 
 
def write_to_file(output_file, results):
    file_path = output_file 
    with open(file_path, 'w') as f:
        for result in results:
            f.write(str(result) + '\n')
    print(f"Reputation results written to {file_path}")

# append to file
def append_to_file(output_file, results):
    file_path = output_file 
    with open(file_path, 'a') as f:
        for result in results:
            f.write(str(result) + '\n')
    print(f"Reputation results written to {file_path}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Find and print unique IP addresses from log files')
        # Read the config file, if it exists
    config = {}
    # if file or dir is passed in via command arg use command args, else use default config file
    if os.path.isfile(DEFAULT_CONFIG_FILE):
        with open(DEFAULT_CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)

    # Get the API key from either the command-line argument or the config file
    parser.add_argument('--api-key', '-k', type=str, help='API key for the AbuseIPDB API')
    parser.add_argument('--file', '-f', type=str, help='Path to a single log file to process')
    parser.add_argument('--dir', '-d', type=str, help='Path to a directory containing log files to process')
    parser.add_argument('--output', '-o', type=str, help='Path to an output file to write the unique IP addresses to')
    parser.add_argument('--check-rep', action='store_true', help='Check the reputation of each unique IP')
    args = parser.parse_args()
    api_key = args.api_key or config.get("api_key")

    if args.file or args.dir:
        log_files = get_log_files(args.file, args.dir)
    else:
        if config.get("file"):
            log_files = get_log_files(config.get("file"), None)
        elif config.get("dir"):
            log_files = get_log_files(None, config.get("dir")) 
        else:
            print("No log file or directory specified in command-line arguments or config file")
            return
    
    unique_ips = set()

    for log_file in log_files:
        unique_ips.update(extract_ip_addresses(log_file))
    
    sorted_ips = sorted(unique_ips)

    if args.output:
        with open(args.output, "w") as f:
            for ip in sorted_ips:
                f.write(ip + "\n")

    if args.output: 
        rep_output_file = args.output
    elif config.get("rep_output_file"):
        rep_output_file = config.get("rep_output_file")
    else:
        rep_output_file = "rep_output.txt"
        
    
    ips = []
    for ip in sorted_ips:
        if ipaddress.IPv4Address(ip).is_global:
            if ipaddress.IPv4Address(ip).is_multicast == False:
                ips.append(ip)
    if args.check_rep or config.get("check_rep"):
        abuseipdb_checker = ReputationChecker(api="abuiseipdb")
        otx_checker = ReputationChecker(api="otx")
        sans_checker = ReputationChecker(api="sans")

        results = []        
        for ip in ips:
            if check_valid(ip):
                api = "abuseipdb"
                results = abuseipdb_checker.check_ips_reputations(api, ips)
        write_to_file(rep_output_file, results)
        print("AbuseIPDB results written to file")

        for ip in ips:
            if check_valid(ip):
            # [todo] Need to tweak the function still - otx response is large
                api = "otx"
                results = otx_checker.check_ips_reputations(api, ips)
        append_to_file(rep_output_file, results)
        print("OTX results written to file") 
        #SANS does not want to be DoSed so only check first 20 IPs
        first_20 = ips[:20]
        for ip in first_20:
            if check_valid(ip):
                api == "sans"
                results = sans_checker.check_ips_reputations(api, ips)
        write_to_file(rep_output_file, results)
        print("SANS results written to file")
        
if __name__ == "__main__":
    main()
    


















































