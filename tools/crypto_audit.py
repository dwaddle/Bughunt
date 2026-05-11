#!/usr/bin/env python3
"""
Crypto-Audit: A tool to identify Cryptographic Failures and Insecure Storage.
Part of the Bughunt project (OWASP A02: Cryptographic Failures).
"""

import requests
import argparse
import re
import sys
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Patterns for sensitive data (API keys, secrets, etc.)
SECRET_PATTERNS = [
    r'(?i)(api[_-]?key|secret|token|auth|password|passwd|access[_-]?key|private[_-]?key)[a-z0-9_]*\s*[:=]\s*["\']([a-z0-9\-/+_=]{16,})["\']',
    r'(?i)bearer\s+[a-z0-9\-\._~+/]+=*',
    r'(?i)ghp_[a-zA-Z0-9]{36}', # GitHub PAT
    r'(?i)AIza[0-9A-Za-z\\-_]{35}', # Google API Key
]

# Patterns for weak cryptographic algorithms
WEAK_ALGO_PATTERNS = [
    r'(?i)(md5|sha1|rc4|des|aes-ecb|cbc-mode)',
    r'(?i) ECB', # Often used in libraries as AES.MODE_ECB
]

# Patterns for data storage
STORAGE_PATTERNS = [
    r'(localStorage|sessionStorage|document\.cookie)',
]

class CryptoAuditor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.scanned_urls = set()

    def audit(self):
        print(f"[*] Starting Cryptographic Audit on: {self.target_url}")
        try:
            response = requests.get(self.target_url, timeout=10)
            self.check_headers(response.headers)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Audit internal scripts
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    self.scan_content("Internal Script", script.string)
                
                # 2. Audit external scripts
                src = script.get('src')
                if src:
                    full_src_url = urljoin(self.target_url, src)
                    if full_src_url not in self.scanned_urls:
                        self.audit_external_script(full_src_url)

        except Exception as e:
            print(f"[x] Error during audit: {e}")

    def check_headers(self, headers):
        print("[*] Checking HTTP Headers for insecure storage...")
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            if 'HttpOnly' not in set_cookie:
                self.log_finding("CRITICAL", "Cookie missing HttpOnly flag", "Set-Cookie header")
            if 'Secure' not in set_cookie and self.target_url.startswith('https'):
                self.log_finding("HIGH", "Cookie missing Secure flag on HTTPS", "Set-Cookie header")

    def audit_external_script(self, url):
        self.scanned_urls.add(url)
        try:
            print(f"[*] Scanning external script: {url}")
            response = requests.get(url, timeout=10)
            self.scan_content(url, response.text)
        except:
            pass

    def scan_content(self, source, content):
        # Scan for Secrets
        for pattern in SECRET_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.log_finding("CRITICAL", f"Potential hardcoded secret found: {match.group(0)[:50]}...", source)

        # Scan for Weak Algos
        for pattern in WEAK_ALGO_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.log_finding("MEDIUM", f"Weak/Legacy cryptographic algorithm found: {match.group(0)}", source)

        # Scan for Storage methods
        for pattern in STORAGE_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.log_finding("LOW", f"Insecure client-side storage method used: {match.group(0)}", source)

    def log_finding(self, severity, title, source):
        finding = {"severity": severity, "title": title, "source": source}
        if finding not in self.findings:
            print(f"[!] [{severity}] {title} (Source: {source})")
            self.findings.append(finding)

def main():
    parser = argparse.ArgumentParser(description="Crypto-Audit (OWASP A02)")
    parser.add_argument("url", help="Target URL to audit")
    args = parser.parse_args()

    auditor = CryptoAuditor(args.url)
    auditor.audit()
    
    if not auditor.findings:
        print("[-] No obvious cryptographic failures detected.")

if __name__ == "__main__":
    main()
