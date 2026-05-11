"""
Config: Central management for wordlists and project-wide settings.
Part of the Bughunt project.
"""

import os

# Base paths for wordlists
SECLISTS_PATH = "/home/rene/projecten/github.com/SecLists"
DIRBUSTER_PATH = "/home/rene/projecten/github.com/dirbuster-wordlist"

# Web Discovery Wordlists
WORDLISTS = {
    "dir_small": os.path.join(DIRBUSTER_PATH, "directory-list-2.3-small.txt"),
    "dir_medium": os.path.join(DIRBUSTER_PATH, "directory-list-2.3-medium.txt"),
    "common": os.path.join(SECLISTS_PATH, "Discovery/Web-Content/common.txt"),
    "api": os.path.join(SECLISTS_PATH, "Discovery/Web-Content/api/api-endpoints-resetted.txt"), # Note: check exact file if needed
    "raft_small": os.path.join(SECLISTS_PATH, "Discovery/Web-Content/raft-small-directories.txt"),
}

# Authentication Wordlists
AUTH_LISTS = {
    "default_creds": os.path.join(SECLISTS_PATH, "Passwords/Default-Credentials/default-passwords.txt"),
    "common_users": os.path.join(SECLISTS_PATH, "Usernames/top-usernames-shortlist.txt"),
}

# Fuzzing / Injection Payloads
PAYLOADS = {
    "lfi": os.path.join(SECLISTS_PATH, "Fuzzing/LFI/LFI-Jhaddix.txt"),
    "sqli": os.path.join(SECLISTS_PATH, "Fuzzing/SQLi/Generic-SQLi.txt"),
    "xss": os.path.join(SECLISTS_PATH, "Fuzzing/XSS/XSS-Jhaddix.txt"),
}

def get_wordlist(key):
    path = WORDLISTS.get(key) or AUTH_LISTS.get(key) or PAYLOADS.get(key)
    if path and os.path.exists(path):
        return path
    return None
