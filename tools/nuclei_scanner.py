#!/usr/bin/env python3
"""
Nuclei-Scanner: A wrapper for the Nuclei template-based vulnerability scanner.
Part of the Bughunt project (OWASP A06: Vulnerable Components).
"""

import subprocess
import argparse
import os
import json

class NucleiScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []

    def run_scan(self, severity=None, tags=None):
        print(f"[*] Starting Nuclei scan on: {self.target_url}")
        
        # Build command
        cmd = ["nuclei", "-u", self.target_url, "-silent", "-jsonl"]
        
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
            
        try:
            # Run nuclei and capture JSONL output
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                for line in result.stdout.splitlines():
                    try:
                        finding = json.loads(line)
                        self.log_finding(finding)
                    except:
                        pass
        except Exception as e:
            print(f"[x] Nuclei scan error: {e}")
            
        return self.findings

    def log_finding(self, finding):
        # Extract relevant info from Nuclei JSON
        info = finding.get('info', {})
        name = info.get('name', 'Unknown')
        sev = info.get('severity', 'info').upper()
        matched = finding.get('matched-at', '')
        
        print(f"[!] [{sev}] Nuclei Hit: {name} ({matched})")
        self.findings.append({
            "severity": sev,
            "name": name,
            "matched": matched,
            "description": info.get('description', '')
        })

def main():
    parser = argparse.ArgumentParser(description="Nuclei-Scanner for Bughunt")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--severity", help="Filter by severity (critical, high, medium, low)")
    parser.add_argument("--tags", help="Filter by tags (cve, exposure, misconfig, etc.)")
    
    args = parser.parse_args()
    
    scanner = NucleiScanner(args.url)
    findings = scanner.run_scan(severity=args.severity, tags=args.tags)
    
    if not findings:
        print("[-] No Nuclei matches found.")

if __name__ == "__main__":
    main()
