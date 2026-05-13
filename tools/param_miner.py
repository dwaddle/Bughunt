#!/usr/bin/env python3
"""
Param-Miner: A tool to identify hidden HTTP parameters.
Part of the Bughunt project (OWASP A01: Broken Access Control).
"""

import requests
import argparse
import sys
import os

# Focused wordlist for common parameter names
COMMON_PARAMS = [
    "id", "user", "admin", "debug", "dev", "test", "page", "file", "path",
    "url", "dest", "redirect", "cmd", "exec", "command", "query", "search",
    "token", "secret", "key", "auth", "role", "config", "settings"
]

def mine_parameters(url, method="GET"):
    print(f"[*] Starting parameter mining on: {url} ({method})")
    
    # Get baseline response
    try:
        baseline = requests.request(method, url, timeout=5)
        baseline_len = len(baseline.text)
        print(f"[*] Baseline response length: {baseline_len}")
    except Exception as e:
        print(f"[!] Error getting baseline: {e}")
        return

    found = []
    for param in COMMON_PARAMS:
        try:
            if method.upper() == "GET":
                target = f"{url}?{param}=test" if "?" not in url else f"{url}&{param}=test"
                response = requests.get(target, timeout=3)
            else:
                response = requests.post(url, data={param: "test"}, timeout=3)
            
            if len(response.text) != baseline_len:
                print(f"[!] Found potential parameter: {param} (Length: {len(response.text)})")
                found.append(param)
        except Exception:
            pass
            
    return found

def main():
    parser = argparse.ArgumentParser(
        description="Param-Miner: Identifies hidden or unlinked HTTP parameters (OWASP A01:2021-Broken Access Control). "
                    "Detects parameters that change application behavior by analyzing response length variations."
    )
    parser.add_argument("url", help="Target URL to probe for hidden parameters")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method to use for parameter mining (default: GET)")
    args = parser.parse_args()
    mine_parameters(args.url, args.method)

if __name__ == "__main__":
    main()
