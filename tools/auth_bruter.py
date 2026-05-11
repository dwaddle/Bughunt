#!/usr/bin/env python3
"""
Auth-Bruter: A tool to test for default credentials and weak passwords.
Part of the Bughunt project.
"""

import requests
import argparse
import sys
import os
try:
    from config import AUTH_LISTS
except ImportError:
    AUTH_LISTS = {"default_creds": None}

# Internal common default credentials as fallback
INTERNAL_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("user", "user"), ("guest", "guest")
]

def load_creds(file_path, limit=50):
    """Loads credentials from a SecLists style file."""
    if not file_path or not os.path.exists(file_path):
        return INTERNAL_CREDS
    
    creds = []
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            
            if ":" in line:
                user, pwd = line.split(":", 1)
                creds.append((user, pwd))
            else:
                # If only password is provided, try with common usernames
                creds.append(("admin", line))
                creds.append(("root", line))
            
            if len(creds) >= limit:
                break
    return creds

def test_auth(url, username_field, password_field, method="POST", wordlist=None):
    print(f"[*] Starting Auth-Brute on {url}")
    
    creds = load_creds(wordlist)
    print(f"[*] Testing {len(creds)} credential pairs...")

    for user, pwd in creds:
        try:
            data = {username_field: user, password_field: pwd}

            if method.upper() == "POST":
                response = requests.post(url, data=data, timeout=5, allow_redirects=False)
            else:
                response = requests.get(url, params=data, timeout=5, allow_redirects=False)

            # Success indicators: 302 Redirect or 200 OK without 'login' keywords
            if response.status_code == 302 or (response.status_code == 200 and "login" not in response.text.lower()):
                print(f"[!] SUCCESS: Found credentials! -> {user}:{pwd}")
                return (user, pwd)
            
        except Exception as e:
            pass # Silent fail for individual attempts

    print("[-] No common credentials found.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Auth-Bruter for Bughunt")
    parser.add_argument("url", help="Target login URL")
    parser.add_argument("--user-field", default="username", help="Username field name")
    parser.add_argument("--pass-field", default="password", help="Password field name")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--wordlist", help="Path to credentials wordlist")
    parser.add_argument("--full", action="store_true", help="Use default SecLists credentials")

    args = parser.parse_args()
    
    w_path = args.wordlist if args.wordlist else (AUTH_LISTS.get("default_creds") if args.full else None)
    test_auth(args.url, args.user_field, args.pass_field, args.method, w_path)

if __name__ == "__main__":
    main()
