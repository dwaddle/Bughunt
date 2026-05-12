#!/usr/bin/env python3
"""
Design-Audit: A tool to identify Insecure Design and architectural flaws.
Part of the Bughunt project (OWASP A04: Insecure Design).
"""

import requests
import argparse

# Common design flaws / exposed endpoints
DESIGN_INDICATORS = {
    "Swagger UI": ["/swagger-ui.html", "/swagger/", "/api/docs", "/v1/swagger.json"],
    "Dev/Debug Endpoints": ["/phpinfo.php", "/info.php", "/status", "/health"],
    "Exposed Versioning": ["/.git/", "/.svn/", "/package-lock.json"],
    "Old/Backup Files": ["/index.php.bak", "/config.php.old", "/backup.sql"]
}

class DesignAuditor:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip("/")
        self.findings = []

    def check_headers(self):
        print("[*] Auditing Security Headers...")
        try:
            response = requests.head(self.target_url, timeout=5)
            headers = response.headers
            missing = []
            for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
                if h not in headers:
                    missing.append(h)
            
            if missing:
                self.log_finding("LOW", f"Missing security headers: {', '.join(missing)}")
        except: pass

    def check_exposed_docs(self):
        print("[*] Auditing for Exposed Documentation & Design Flaws...")
        for category, paths in DESIGN_INDICATORS.items():
            for path in paths:
                try:
                    url = f"{self.target_url}{path}"
                    res = requests.head(url, timeout=3, allow_redirects=True)
                    if res.status_code == 200:
                        self.log_finding("HIGH", f"Exposed {category} found: {path}")
                except: pass

    def log_finding(self, severity, title):
        print(f"[!] [{severity}] {title}")
        self.findings.append({"severity": severity, "title": title})

def main():
    parser = argparse.ArgumentParser(description="Design-Audit (OWASP A04)")
    parser.add_argument("url", help="Target Base URL")
    args = parser.parse_args()
    
    auditor = DesignAuditor(args.url)
    auditor.check_headers()
    auditor.check_exposed_docs()

if __name__ == "__main__":
    main()
