#!/usr/bin/env python3
"""
Directory-Scanner: A fast, focused directory and API endpoint discoverer.
Part of the Bughunt project.
"""

import requests
import argparse
import sys
import os

# Focused wordlist for common high-impact targets (Fast Scan)
FAST_PATHS = [
    "admin", "administrator", "login", "api", "api/v1", "api/v2", ".env", 
    "config", "settings", "backup", "test", "dev", "debug", ".git", "robots.txt"
]

DEFAULT_WORDLIST = "/home/rene/projecten/github.com/dirbuster-wordlist/directory-list-2.3-small.txt"

def load_wordlist(file_path, limit=100):
    """Loads a wordlist from a file, skipping comments and limiting the size for speed."""
    if not os.path.exists(file_path):
        return []
    
    words = []
    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)
                if len(words) >= limit:
                    break
    return words

def scan_directories(url, wordlist_path=None, fast=True):
    print(f"[*] Starting directory discovery on {url}")
    found = []
    
    # Decide which paths to use
    if fast:
        paths = FAST_PATHS
        print("[*] Using internal fast-scan wordlist.")
    elif wordlist_path and os.path.exists(wordlist_path):
        paths = load_wordlist(wordlist_path)
        print(f"[*] Using wordlist: {wordlist_path} (Limited to first 100 entries)")
    else:
        paths = FAST_PATHS
        print("[!] Wordlist not found, falling back to fast-scan.")

    base_url = url if url.endswith("/") else f"{url}/"
    
    for path in paths:
        target = f"{base_url}{path}"
        try:
            response = requests.head(target, timeout=2, allow_redirects=True)
            if response.status_code in [200, 204, 301, 302, 401, 403]:
                print(f"[+] Found: {target} (Status: {response.status_code})")
                found.append({"url": target, "status": response.status_code})
        except Exception:
            pass
            
    return found

def main():
    parser = argparse.ArgumentParser(description="Directory-Scanner for Bughunt")
    parser.add_argument("url", help="Target Base URL")
    parser.add_argument("--wordlist", help="Path to wordlist file")
    parser.add_argument("--full", action="store_true", help="Run a fuller scan using the default DirBuster list")
    
    args = parser.parse_args()
    
    w_path = args.wordlist if args.wordlist else (DEFAULT_WORDLIST if args.full else None)
    scan_directories(args.url, wordlist_path=w_path, fast=not (args.wordlist or args.full))

if __name__ == "__main__":
    main()
