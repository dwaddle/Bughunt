#!/usr/bin/env python3
"""
SQLi-Tester: A tool to identify SQL Injection vulnerabilities.
Part of the Bughunt project (OWASP A03: Injection).
"""

import requests
import argparse
import os
import sys

try:
    from config import PAYLOADS
except ImportError:
    PAYLOADS = {"sqli": None}

# Error patterns for different SQL databases
SQL_ERRORS = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysql"],
    "PostgreSQL": ["vulnerable to postgresql injection", "invalid input syntax for type"],
    "Microsoft SQL Server": ["unclosed quotation mark after the character string", "sql server error"],
    "Oracle": ["ora-00933: sql command not properly ended", "oracle error"],
    "SQLite": ["sqlite3.operationalerror:", "unrecognized token:"]
}

def load_payloads(file_path, limit=100):
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
    
    # Minimal fallback SQLi payloads
    return ["'", "\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1--", "admin' --"]

def scan_sqli(url, wordlist_path=None):
    print(f"[*] Starting SQLi scan on: {url}")
    
    if "FUZZ" not in url:
        print("[!] Error: No 'FUZZ' keyword found in URL.")
        return

    payloads = load_payloads(wordlist_path)
    print(f"[*] Testing {len(payloads)} payloads...")

    found = []

    for payload in payloads:
        target = url.replace("FUZZ", payload)
        try:
            response = requests.get(target, timeout=5)
            
            # Check for SQL error messages in the response
            for db, errors in SQL_ERRORS.items():
                for error in errors:
                    if error in response.text.lower():
                        print(f"\n[!] SQL INJECTION DETECTED (Error-based)!")
                        print(f"    DB:      {db}")
                        print(f"    Payload: {payload}")
                        print(f"    URL:     {target}\n")
                        found.append({"type": "Error-based", "db": db, "payload": payload})
                        break
            
            # Simple Boolean-based check (very basic)
            # If 'true' payload gives 200 and 'false' payload gives something else, it's a hint
            # This is complex to automate reliably without more logic, but we look for indicators
            
        except Exception:
            pass

    if not found:
        print("[-] No SQLi vulnerabilities detected via error patterns.")
    
    return found

def main():
    parser = argparse.ArgumentParser(
        description="SQLi-Tester: Identifies SQL Injection vulnerabilities (OWASP A03:2021-Injection). "
                    "Probes for error-based SQL injection by injecting common payloads and monitoring for database error messages."
    )
    parser.add_argument("url", help="Target URL with the 'FUZZ' keyword in the vulnerable parameter (e.g., 'http://target.com/api?id=FUZZ')")
    parser.add_argument("--wordlist", help="Path to a custom wordlist of SQLi payloads")
    parser.add_argument("--full", action="store_true", help="Use the project's default SecLists-based SQLi payload list")

    args = parser.parse_args()
    w_path = args.wordlist if args.wordlist else (PAYLOADS.get("sqli") if args.full else None)
    scan_sqli(args.url, w_path)

if __name__ == "__main__":
    main()
