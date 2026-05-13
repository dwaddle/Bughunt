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
    print(f"[*] {Colors.BLUE}Enumerating related domains{Colors.RESET} (via crt.sh)...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry['name_value'].lower()
                for part in name.split('\n'):
                    if not part.startswith('*.'): 
                        subdomains.add(part)
            
            if subdomains:
                print(f"    - Found {Colors.GREEN}{len(subdomains)}{Colors.RESET} unique related domains!")
                for sub in sorted(subdomains):
                    # Check if domain is out of scope
                    is_oos = any(pattern in sub for pattern in out_of_scope)
                    if is_oos:
                        print(f"      {Colors.RED}[OUT OF SCOPE] > {sub}{Colors.RESET}")
                    else:
                        print(f"      {Colors.GREEN}[IN SCOPE]     > {sub}{Colors.RESET}")
                return list(subdomains)
    except Exception as e:
        print(f"    {Colors.RED}[x] Error fetching subdomains: {e}{Colors.RESET}")
    return []

def main():
    parser = argparse.ArgumentParser(
        description="Domain-Explorer: Identifies AS number and discovers subdomains for a target domain."
    )
    parser.add_argument("domain", help="Target domain (e.g., 'example.com')")
    parser.add_argument("--out-of-scope", "-oos", help="Comma-separated list of OOS domains or keywords")
    args = parser.parse_args()

    oos_list = args.out_of_scope.split(",") if args.out_of_scope else []

    get_as_info(args.domain)
    get_subdomains(args.domain, out_of_scope=oos_list)

if __name__ == "__main__":
    main()

