#!/usr/bin/env python3
"""
Verbose-Checker: A tool to identify verbose error messages and hidden debug endpoints.
Part of the Bughunt project.
"""

import requests
import json
import argparse
import sys

# Common payloads to trigger errors or debug info
PAYLOADS = [
    "not_a_number",      # Type mismatch
    "'",                 # SQL injection / string break
    "\"",                # SQL injection / string break
    "$(id)",             # Command injection attempt
    "{{7*7}}",           # SSTI attempt
    "debug",             # Common hidden trigger
    "test",              # Common hidden trigger
    "1337",              # Unexpected large/specific number
    "0",                 # Boundary case
    "-1",                # Boundary case
    "None",              # Null byte / None type
    "{}",                # Empty JSON object
    "[]",                # Empty JSON array
]

# Keywords that indicate a verbose error or sensitive leak
SENSITIVE_KEYWORDS = [
    "traceback",
    "stack trace",
    "exception",
    "valueerror",
    "syntaxerror",
    "flag",
    "thm{",
    "password",
    "secret",
    "internal_secret",
    "debug_info",
    "admin_token"
]

def scan_endpoint(url, method="GET", param_name=None):
    print(f"[*] Starting scan on {url} ({method})")
    results = []

    for payload in PAYLOADS:
        try:
            if method.upper() == "GET":
                # For GET, we assume the payload is in the URL path if no param_name is provided
                target_url = url.replace("FUZZ", str(payload)) if "FUZZ" in url else f"{url}/{payload}"
                response = requests.get(target_url, timeout=5)
            else:
                # For POST, we send JSON data
                data = {param_name: payload} if param_name else {"data": payload}
                response = requests.post(url, json=data, timeout=5)

            # Analyze response
            found_keywords = [k for k in SENSITIVE_KEYWORDS if k in response.text.lower()]
            
            if found_keywords or response.status_code >= 500:
                print(f"[!] POTENTIAL FINDING with payload: {payload}")
                print(f"    Status: {response.status_code}")
                print(f"    Keywords: {', '.join(found_keywords)}")
                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "found_keywords": found_keywords,
                    "preview": response.text[:200]
                })

        except Exception as e:
            print(f"[x] Error with payload {payload}: {e}")

    return results

def main():
    parser = argparse.ArgumentParser(description="Verbose-Checker for Bughunt")
    parser.add_argument("url", help="Target URL (use FUZZ for position in GET requests)")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method (default: GET)")
    parser.add_argument("--param", help="Parameter name for POST requests (default: data)")
    parser.add_argument("--output", help="Save results to JSON file")

    args = parser.parse_args()

    results = scan_endpoint(args.url, args.method, args.param)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[*] Results saved to {args.output}")

if __name__ == "__main__":
    main()
