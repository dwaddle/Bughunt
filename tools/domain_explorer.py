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

def get_as_info(domain):
    print(f"[*] Fetching AS information for: {domain}")
    try:
        # 1. Resolve domain to IP
        ip = socket.gethostbyname(domain)
        print(f"    - IP Address: {ip}")
        
        # 2. Get AS info via ip-api.com
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,as,isp,org", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                as_info = data.get('as', 'Unknown AS')
                isp = data.get('isp', 'Unknown ISP')
                print(f"    - AS Number: {as_info}")
                print(f"    - Provider:  {isp}")
                return {"ip": ip, "as": as_info, "provider": isp}
    except Exception as e:
        print(f"    [x] Error fetching AS info: {e}")
    return None

def get_subdomains(domain):
    print(f"[*] Enumerating related domains (via crt.sh)...")
    subdomains = set()
    try:
        # Query crt.sh for SSL certificates
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry['name_value'].lower()
                # Split multiple names in one entry (wildcards/multiple SANs)
                for part in name.split('\n'):
                    if not part.startswith('*.'): # Ignore wildcard notation
                        subdomains.add(part)
            
            if subdomains:
                print(f"    - Found {len(subdomains)} unique related domains!")
                for sub in sorted(subdomains)[:10]: # Show top 10
                    print(f"      > {sub}")
                if len(subdomains) > 10:
                    print(f"      > ... ({len(subdomains) - 10} more)")
                return list(subdomains)
    except Exception as e:
        print(f"    [x] Error fetching subdomains: {e}")
    return []

def main():
    parser = argparse.ArgumentParser(
        description="Domain-Explorer: Identifies AS number and discovers subdomains for a target domain."
    )
    parser.add_argument("domain", help="Target domain (e.g., 'example.com')")
    args = parser.parse_args()

    as_info = get_as_info(args.domain)
    subdomains = get_subdomains(args.domain)

    if not as_info and not subdomains:
        print("[-] No significant domain information found.")

if __name__ == "__main__":
    main()
