#!/usr/bin/env python3
"""
Master-Recon: The orchestrator for the Bughunt reconnaissance phase.
It runs Nmap, parses the output, and automatically triggers vulnerability-specific tools.
"""

import subprocess
import requests
import argparse
import os
import sys
import re
import xml.etree.ElementTree as ET
from datetime import datetime
import time

# Import our custom logic
sys.path.append(os.path.join(os.path.dirname(__file__)))
try:
    from directory_scanner import scan_directories
except ImportError:
    def scan_directories(url, ua_type="desktop"): return []

try:
    from ai_analyzer import get_ai_insight
    HAS_AI = True
except ImportError:
    HAS_AI = False

try:
    from nuclei_scanner import NucleiScanner
    HAS_NUCLEI = True
except ImportError:
    HAS_NUCLEI = False

# ANSI Color Codes
class Colors:
    CRITICAL = '\033[91m\033[1m' # Bold Red
    HIGH = '\033[91m'            # Red
    MEDIUM = '\033[93m'          # Yellow
    LOW = '\033[92m'             # Green
    INFO = '\033[94m'            # Blue
    DIM = '\033[90m'             # Gray
    RESET = '\033[0m'

def get_severity(score):
    try:
        s = float(score)
        if s >= 9.0: return "CRITICAL", Colors.CRITICAL
        if s >= 7.0: return "HIGH", Colors.HIGH
        if s >= 4.0: return "MEDIUM", Colors.MEDIUM
        return "LOW", Colors.LOW
    except:
        return "UNKNOWN", Colors.RESET

def get_cve_description(cve_id):
    """Fetches a short summary for a CVE ID from NIST NVD API."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                descriptions = vulnerabilities[0].get('cve', {}).get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        summary = desc.get('value', 'No description available.')
                        return (summary[:150] + '...') if len(summary) > 150 else summary
    except:
        pass
    return "Description lookup failed or unavailable for this CVE."

def parse_vulners_output(output):
    """Parses vulners output and returns formatted lines with severity and descriptions."""
    lines = output.split('\n')
    formatted_console = []
    formatted_report = []
    findings = []
    
    seen_cves = set()
    cve_count = 0
    
    for line in lines:
        match = re.search(r'(CVE-\d{4}-\d+)\s+(\d+\.?\d*)', line)
        if match:
            cve_id = match.group(1)
            score = match.group(2)
            
            if cve_id in seen_cves: continue
            seen_cves.add(cve_id)
            cve_count += 1
            
            label, color = get_severity(score)
            
            description = ""
            if cve_count <= 3: # Limit to top 3 for speed
                description = get_cve_description(cve_id)
            
            findings.append({"id": cve_id, "score": score, "label": label})
            
            console_line = f"      {color}[{label}] {cve_id} (Score: {score}){Colors.RESET}"
            if description:
                console_line += f"\n      {Colors.DIM}>> {description}{Colors.RESET}"
            
            report_line = f"      [{label}] {cve_id} (Score: {score})"
            if description:
                report_line += f"\n      >> {description}"
            
            formatted_console.append(console_line)
            formatted_report.append(report_line)
        else:
            if line.strip() and "http" not in line:
                formatted_console.append(f"      {line.strip()}")
                formatted_report.append(f"      {line.strip()}")
                
    return "\n".join(formatted_console), "\n".join(formatted_report), findings

def run_nmap(target, port=None):
    xml_file = "nmap_results.xml"
    port_arg = f"-p {port}" if port else ""
    print(f"[*] Running Nmap scan on {target} {f'port {port}' if port else 'common ports'}...")
    cmd = f"nmap -sV --script vulners -T4 {port_arg} -oX {xml_file} {target}"
    subprocess.run(cmd, shell=True, check=True)
    return xml_file

def get_exploits(service=None, version="", cve_id=None):
    if cve_id:
        cmd = f"python3 tools/exploit_matcher.py --cve '{cve_id}'"
    else:
        cmd = f"python3 tools/exploit_matcher.py --service '{service}' --version '{version}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def generate_tactical_plan(findings_summary):
    if not HAS_AI:
        return "AI not available for tactical planning."

    print(f"[*] Generating AI Tactical Attack Plan...")
    prompt = f"""
    You are a Lead Penetration Tester. Review these findings and provide a 3-step Tactical Attack Plan.
    Focus on the most likely path to Root/Admin.

    Findings Summary:
    {findings_summary}

    Structure:
    - Phase 1: Entry Point (Highest priority)
    - Phase 2: Exploitation Strategy
    - Phase 3: Post-Exploitation/Lateral Movement
    """
    return get_ai_insight("Tactical Planning", prompt)

def create_org_report(target_full, xml_file):
    safe_name = target_full.replace('.', '_').replace(':', '_')
    report_path = f"notes/{safe_name}.org"
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    action_items = []
    recon_details = []
    full_findings_log = []
    
    for host in root.findall('host'):
        addr = host.find('address').get('addr')
        for port_elem in host.findall('.//port'):
            portid = port_elem.get('portid')
            state = port_elem.find('state').get('state')
            if state == 'open':
                service_elem = port_elem.find('service')
                service_name = service_elem.get('name') if service_elem is not None else "unknown"
                product = service_elem.get('product', '') if service_elem is not None else ""
                version = service_elem.get('version', '') if service_elem is not None else ""
                
                print(f"[+] {Colors.INFO}Found Port {portid}{Colors.RESET}: {product} {version}")
                full_findings_log.append(f"Port {portid}: {product} {version}")
                
                port_section = [f"*** Port {portid}: {service_name}\n", f"- Product: {product}\n", f"- Version: {version}\n"]
                
                # CVEs
                script_elem = port_elem.find(".//script[@id='vulners']")
                if script_elem is not None:
                    console_cves, report_cves, cve_list = parse_vulners_output(script_elem.get('output'))
                    print(f"    - Potential CVEs Found:")
                    print(console_cves)
                    port_section.append("- Potential CVEs:\n#+BEGIN_EXAMPLE\n" + report_cves + "\n#+END_EXAMPLE\n")
                    
                    for cve in cve_list:
                        full_findings_log.append(f"  - CVE: {cve['id']} (Score: {cve['score']})")
                    
                    for cve in cve_list[:2]:
                        exploits = get_exploits(cve_id=cve['id'])
                        if "Found" in exploits:
                            port_section.append(f"- Specific Exploit Found for {cve['id']}:\n#+BEGIN_EXAMPLE\n" + exploits + "#+END_EXAMPLE\n")
                            action_items.append(f"| {cve['label']} | Specific Exploit found for {cve['id']} | Run: ~python3 tools/exploit_matcher.py --cve {cve['id']}~ |")
                        
                        if cve['label'] in ['CRITICAL', 'HIGH'] and "Found" not in exploits:
                            action_items.append(f"| {cve['label']} | CVE Found on port {portid} ({cve['id']}) | Investigate with Exploit-Matcher |")

                # General Exploits
                if product:
                    general_exploits = get_exploits(service=product, version=version)
                    port_section.append("- General Exploit Matcher Output:\n#+BEGIN_EXAMPLE\n" + general_exploits + "#+END_EXAMPLE\n")
                    if "Found" in general_exploits:
                        action_items.append(f"| HIGH | Known Exploit for {product} {version} | Run: ~python3 tools/exploit_matcher.py --service '{product}' --version '{version}'~ |")

                # Nuclei Scan
                if HAS_NUCLEI and (service_name == "http" or portid in ["80", "443", "5002", "5003", "5004", "5005", "8080"]):
                    url = f"http://{addr}:{portid}"
                    print(f"    - Running Nuclei breedte-scan...")
                    scanner = NucleiScanner(url)
                    nuclei_findings = scanner.run_scan(severity="critical,high,medium")
                    
                    if nuclei_findings:
                        port_section.append("- Nuclei Findings:\n")
                        for f in nuclei_findings:
                            port_section.append(f"  - [{f['severity']}] {f['name']} ({f['matched']})\n")
                            action_items.append(f"| {f['severity']} | Nuclei Hit: {f['name']} | Target: {f['matched']} |")
                            full_findings_log.append(f"  - Nuclei hit on {portid}: {f['name']}")

                # HTTP Specific Actions with AI
                if service_name == "http" or portid in ["80", "443", "5002", "5003", "5004", "5005", "8080"]:
                    url = f"http://{addr}:{portid}"
                    print(f"    - Performing Intelligent Analysis...")
                    try:
                        res = requests.get(url, timeout=5)
                        content = res.text
                        
                        # AI Expert Opinion
                        if HAS_AI:
                            ai_opinion = get_ai_insight("HTTP Response", content)
                            port_section.append("- AI Expert Opinion:\n#+BEGIN_QUOTE\n" + ai_opinion + "\n#+END_QUOTE\n")
                            action_items.append(f"| AI | Contextual Insight on port {portid} | Review AI Expert Opinion in report |")
                            full_findings_log.append(f"  - AI Insight for {url}: {ai_opinion[:100]}...")

                        # Manual Hints
                        if "mobile" in content.lower():
                            print(f"      [!] Hint detected: 'Mobile' mentioned. Retrying Directory Discovery with Mobile UA.")
                            scan_directories(url, ua_type="mobile")
                            action_items.append(f"| HIGH | Mobile-only app detected | Run: ~python3 tools/directory_scanner.py {url} --ua mobile~ |")
                        
                        if "admin" in content.lower() or "login" in content.lower():
                            action_items.append(f"| CRITICAL | Admin/Login Page found | Run: ~python3 tools/auth_bruter.py {url}/login~ |")
                            
                    except Exception as e:
                        print(f"      [x] Analysis error: {e}")

                    # Standard Tools
                    print(f"    - Starting Parameter Mining...")
                    action_items.append(f"| MEDIUM | Hidden Parameter Discovery | Run: ~python3 tools/param_miner.py {url}/~ |")
                    
                    port_section.append(f"- Recommended Scan:\n#+BEGIN_SRC bash\npython3 tools/verbose_checker.py http://{addr}:{portid}/FUZZ\n#+END_SRC\n")

                recon_details.append("".join(port_section))

    # After collecting all data, generate tactical plan
    tactical_plan = generate_tactical_plan("\n".join(full_findings_log))

    with open(report_path, "w") as f:
        f.write(f"#+TITLE: AI-Powered Recon Report: {target_full}\n")
        f.write(f"#+AUTHOR: Bughunt Master-Recon\n")
        f.write(f"#+DATE: {datetime.now().strftime('[%Y-%m-%d %a]')}\n\n")
        
        f.write("* 🗺️ AI TACTICAL ATTACK PLAN\n")
        f.write("#+BEGIN_QUOTE\n" + tactical_plan + "\n#+END_QUOTE\n\n")

        f.write("* 🔥 IMMEDIATE ACTION PLAN\n")
        f.write("Below are the most critical findings that require immediate attention:\n\n")
        if action_items:
            f.write("| Severity | Finding | Recommended Action |\n")
            f.write("|----------+---------+--------------------|\n")
            for item in action_items:
                f.write(item + "\n")
        else:
            f.write("- No critical automated actions identified yet.\n")
        f.write("\n")
        
        f.write("* Reconnaissance Details\n")
        for detail in recon_details:
            f.write(detail + "\n")
            
    print(f"\n[+] AI-Powered Report generated: {report_path}")
    return report_path

def main():
    parser = argparse.ArgumentParser(
        description="Master-Recon: The central orchestrator for the Bughunt reconnaissance phase. "
                    "Performs Nmap scans, service versioning, and automatically triggers specialized "
                    "scanners to generate a Tactical Attack Plan and Org-mode report."
    )
    parser.add_argument("target", help="Target IP address, hostname, or IP:Port combination (e.g., '192.168.1.1', 'site.com:8080')")
    args = parser.parse_args()

    target = args.target
    port = None
    if ":" in target:
        target, port = target.split(":", 1)

    try:
        if not os.path.exists("notes"):
            os.makedirs("notes")
        xml_output = run_nmap(target, port)
        report_file = create_org_report(args.target, xml_output)
        print(f"\n[*] Reconnaissance phase completed. Review {report_file}")
    except Exception as e:
        print(f"[x] Critical Error: {e}")

if __name__ == "__main__":
    main()
