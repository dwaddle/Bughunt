#!/usr/bin/env python3
"""
Directory-Scanner: A fast, focused directory and API endpoint discoverer.
Part of the Bughunt project.
"""

import requests
import argparse
import sys

# Focused wordlist for common high-impact targets
COMMON_PATHS = [
    "admin", "administrator", "login", "api", "api/v1", "api/v2", "v1", "v2",
    ".env", "config", "settings", "backup", "bak", "old", "test", "dev",
    "debug", "console", "shell", "status", "health", ".git", ".svn",
    "robots.txt", "security.txt", "uploads", "images", "assets", "static",
    "private", "confidential", "db", "database", "sql"
]

def scan_directories(url):
    print(f"[*] Starting directory discovery on {url}")
    found = []
    
    # Ensure URL ends with / for appending
    base_url = url if url.endswith("/") else f"{url}/"
    
    for path in COMMON_PATHS:
        target = f"{base_url}{path}"
        try:
            # Using head for speed, falling back to get if needed
            response = requests.head(target, timeout=3, allow_redirects=True)
            if response.status_code in [200, 204, 301, 302, 401, 403]:
                print(f"[+] Found: {target} (Status: {response.status_code})")
                found.append({"url": target, "status": response.status_code})
        except Exception:
            pass
            
    return found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Directory-Scanner")
    parser.add_argument("url", help="Target Base URL")
    args = parser.parse_args()
    scan_directories(args.url)
