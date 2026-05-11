#!/usr/bin/env python3
"""
Auth-Bruter: A tool to test for default credentials and weak passwords.
Part of the Bughunt project.
"""

import requests
import argparse
import sys

# Common default credentials (username, password)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", ""),
    ("administrator", "password"),
    ("admin", "welcome"),
    ("admin", "secret"),
]

def test_auth(url, username_field, password_field, method="POST", extra_data=None):
    print(f"[*] Starting Auth-Brute on {url}")
    print(f"[*] Testing {len(DEFAULT_CREDS)} common credential pairs...")

    for user, pwd in DEFAULT_CREDS:
        try:
            data = {username_field: user, password_field: pwd}
            if extra_data:
                data.update(extra_data)

            if method.upper() == "POST":
                response = requests.post(url, data=data, timeout=5, allow_redirects=False)
            else:
                response = requests.get(url, params=data, timeout=5, allow_redirects=False)

            # Analyze response to determine success
            # Common indicators of success: 
            # 1. 302 Redirect (often to a dashboard)
            # 2. 200 OK but different content length or keywords
            # This is a simplified check
            if response.status_code == 302 or (response.status_code == 200 and "login" not in response.text.lower()):
                print(f"[!] SUCCESS: Found credentials! -> {user}:{pwd}")
                return (user, pwd)
            
        except Exception as e:
            print(f"[x] Error testing {user}:{pwd} -> {e}")

    print("[-] No common credentials found.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Auth-Bruter for Bughunt")
    parser.add_argument("url", help="Target login URL")
    parser.add_argument("--user-field", default="username", help="Name of the username field (default: username)")
    parser.add_argument("--pass-field", default="password", help="Name of the password field (default: password)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP method (default: POST)")

    args = parser.parse_args()

    test_auth(args.url, args.user_field, args.pass_field, args.method)

if __name__ == "__main__":
    main()
