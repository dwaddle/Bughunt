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

def load_wordlist(file_path, limit=200):
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

# Common User-Agents for discovery
USER_AGENTS = {
    "desktop": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bughunt/1.0",
    "mobile": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "bot": "Googlebot/2.1 (+http://www.google.com/bot.html)"
}

def scan_directories(url, wordlist_path=None, fast=True, limit=200, ua_type="desktop"):
    print(f"[*] Starting directory discovery on {url} (UA: {ua_type})")
    found = []
    
    headers = {'User-Agent': USER_AGENTS.get(ua_type, USER_AGENTS["desktop"])}
    
    # ... logic stays same
    for path in paths:
        target = f"{base_url}{path}"
        try:
            response = requests.head(target, headers=headers, timeout=2, allow_redirects=True)
            if response.status_code in [200, 204, 301, 302, 401, 403]:
                print(f"[+] Found: {target} (Status: {response.status_code})")
                found.append({"url": target, "status": response.status_code})
        except Exception:
            pass
            
    return found

def main():
    parser = argparse.ArgumentParser(
        description="Directory-Scanner: A fast, focused tool for discovering hidden directories and API endpoints. "
                    "Identifies forgotten assets, sensitive paths, and potential entry points for further testing."
    )
    parser.add_argument("url", help="Target Base URL where the directory scan will start")
    parser.add_argument("--wordlist", help="Path to a custom wordlist file for directory discovery")
    parser.add_argument("--full", action="store_true", help="Perform a more comprehensive scan using the default project wordlist")
    parser.add_argument("--limit", type=int, default=200, help="Maximum number of wordlist entries to test (default: 200)")
    parser.add_argument("--ua", default="desktop", choices=["desktop", "mobile", "bot"], 
                        help="Specify the User-Agent type to use for requests (default: desktop)")
    
    args = parser.parse_args()
    w_path = args.wordlist if args.wordlist else (DEFAULT_WORDLIST if args.full else None)
    scan_directories(args.url, wordlist_path=w_path, fast=not (args.wordlist or args.full), limit=args.limit, ua_type=args.ua)

if __name__ == "__main__":
    main()
