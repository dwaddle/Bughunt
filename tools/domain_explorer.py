#!/usr/bin/env python3
"""
Domain-Explorer: Identifies AS number and related subdomains for a given domain.
Part of the Bughunt project (OWASP A01: Broken Access Control / Recon).
"""

import requests
import argparse
import socket
import json
import sys

# ANSI Color Codes for consistency
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    HEADER = '\033[95m\033[1m'
    RESET = '\033[0m'

def get_as_info(domain):
    print(f"[*] {Colors.BLUE}Fetching AS information{Colors.RESET} for: {Colors.HEADER}{domain}{Colors.RESET}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"    - IP Address: {ip}")
        
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,as,isp,org", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                as_info = data.get('as', 'Unknown AS')
                isp = data.get('isp', 'Unknown ISP')
                print(f"    - AS Number: {Colors.YELLOW}{as_info}{Colors.RESET}")
                print(f"    - Provider:  {isp}")
                return {"ip": ip, "as": as_info, "provider": isp}
    except Exception as e:
        print(f"    {Colors.RED}[x] Error fetching AS info: {e}{Colors.RESET}")
    return None

def get_subdomains(domain, out_of_scope=[]):
    print(f"[*] {Colors.BLUE}Enumerating related domains{Colors.RESET} (via crt.sh - this can take a while for large domains)...")
    subdomains = set()
    try:
        # Query crt.sh for SSL certificates with a much larger timeout
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=60) # Increased to 60s
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry['name_value'].lower()
                for part in name.split('\n'):
                    # Basic cleaning
                    part = part.strip().replace('*.', '')
                    if part and domain in part:
                        subdomains.add(part)
            
            if subdomains:
                sorted_subs = sorted(list(subdomains))
                print(f"    - Found {Colors.GREEN}{len(sorted_subs)}{Colors.RESET} unique related domains!")
                return sorted_subs
    except requests.exceptions.Timeout:
        print(f"    {Colors.YELLOW}[!] crt.sh timed out. Domain might be too large for a single request.{Colors.RESET}")
    except Exception as e:
        print(f"    {Colors.RED}[x] Error fetching subdomains: {e}{Colors.RESET}")
    return []

def main():
    parser = argparse.ArgumentParser(
        description="Domain-Explorer: Identifies AS number and discovers subdomains for a target domain."
    )
    parser.add_argument("domain", help="Target domain (e.g., 'example.com')")
    parser.add_argument("--out-of-scope", "-oos", help="Comma-separated list OR path to a text file with OOS domains/keywords")
    parser.add_argument("--output", "-o", help="Save the list of IN SCOPE domains to a file")
    args = parser.parse_args()

    # Load OOS from file or string
    oos_list = []
    if args.out_of_scope:
        if os.path.exists(args.out_of_scope):
            with open(args.out_of_scope, 'r') as f:
                oos_list = [line.strip().lower() for line in f if line.strip()]
        else:
            oos_list = [item.strip().lower() for item in args.out_of_scope.split(",")]

    get_as_info(args.domain)
    all_subs = get_subdomains(args.domain, out_of_scope=oos_list)
    
    in_scope_subs = []
    if all_subs:
        print(f"\n{Colors.HEADER}--- DOMAIN INVENTORY ---{Colors.RESET}")
        for sub in all_subs:
            is_oos = any(pattern in sub for pattern in oos_list)
            if is_oos:
                print(f"      {Colors.RED}[OUT OF SCOPE] > {sub}{Colors.RESET}")
            else:
                print(f"      {Colors.GREEN}[IN SCOPE]     > {sub}{Colors.RESET}")
                in_scope_subs.append(sub)

    if args.output and in_scope_subs:
        with open(args.output, 'w') as f:
            for sub in in_scope_subs:
                f.write(sub + "\n")
        print(f"\n[+] {Colors.SUCCESS}In-scope domains saved to{Colors.RESET}: {args.output}")

if __name__ == "__main__":
    main()

