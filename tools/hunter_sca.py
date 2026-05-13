#!/usr/bin/env python3
"""
Hunter-SCA: Software Composition Analysis tool.
Part of the Bughunt project (OWASP A08: Software and Data Integrity Failures).
"""

import requests
import argparse
import re
import os
import json

# Common dependency files and their types
DEP_FILES = {
    "requirements.txt": "Python",
    "package.json": "Node.js",
    "composer.json": "PHP",
    "pom.xml": "Java",
    "Gemfile": "Ruby"
}

# Known risky libraries or patterns (Simplified for this tool)
RISKY_COMPONENTS = {
    "flask": "Check for 'debug=True' or hidden debug endpoints (/console).",
    "werkzeug": "Known to have an interactive debugger that can lead to RCE.",
    "django": "Ensure SECRET_KEY is not leaked and DEBUG is False.",
    "express": "Check for environment-specific leakages.",
}

class HunterSCA:
    def __init__(self, target_url=None):
        self.target_url = target_url
        self.findings = []

    def audit_remote_file(self, filename):
        if not self.target_url: return
        
        full_url = f"{self.target_url}/{filename}" if not self.target_url.endswith('/') else f"{self.target_url}{filename}"
        print(f"[*] Auditing remote dependency file: {full_url}")
        
        try:
            response = requests.get(full_url, timeout=10)
            if response.status_code == 200:
                print(f"[!] Found {filename}! Analyzing...")
                self.parse_content(filename, response.text)
            else:
                print(f"[-] {filename} not found (Status: {response.status_code})")
        except Exception as e:
            print(f"[x] Error accessing {filename}: {e}")

    def parse_content(self, filename, content):
        file_type = DEP_FILES.get(filename, "Unknown")
        print(f"[*] Detected {file_type} environment.")
        
        # Simple extraction logic
        if file_type == "Python":
            # Match: library==version
            deps = re.findall(r'^([a-zA-Z0-9\-_]+)', content, re.MULTILINE)
            for dep in deps:
                self.check_risky(dep, "requirements.txt")
        
        elif file_type == "Node.js":
            try:
                data = json.loads(content)
                all_deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                for dep in all_deps:
                    self.check_risky(dep, "package.json")
            except:
                print("[!] Failed to parse package.json as JSON.")

    def check_risky(self, name, source):
        name_lower = name.lower()
        if name_lower in RISKY_COMPONENTS:
            title = f"Potentially risky component found: {name}"
            note = RISKY_COMPONENTS[name_lower]
            self.log_finding("HIGH", title, f"{source} (Note: {note})")

    def log_finding(self, severity, title, source):
        print(f"[!] [{severity}] {title} (Source: {source})")
        self.findings.append({"severity": severity, "title": title, "source": source})

def main():
    parser = argparse.ArgumentParser(
        description="Hunter-SCA: Software Composition Analysis (OWASP A08:2021-Software and Data Integrity Failures). "
                    "Identifies vulnerabilities in third-party components by scanning for exposed dependency files."
    )
    parser.add_argument("url", help="Base URL of the target web application to scan for exposed dependency files")
    parser.add_argument("--scan-all", action="store_true", help="Scan for all common dependency files (e.g., requirements.txt, package.json, composer.json)")
    args = parser.parse_args()

    sca = HunterSCA(args.url)
    
    files_to_scan = DEP_FILES.keys() if args.scan_all else ["requirements.txt", "package.json"]
    
    for f in files_to_scan:
        sca.audit_remote_file(f)

    if not sca.findings:
        print("[-] No obvious supply chain risks found in common dependency files.")

if __name__ == "__main__":
    main()
