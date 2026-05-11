#!/usr/bin/env python3
"""
Master-Recon: The orchestrator for the Bughunt reconnaissance phase.
It runs Nmap, parses the output, and automatically triggers vulnerability-specific tools.
"""

import subprocess
import argparse
import os
import xml.etree.ElementTree as ET
from datetime import datetime

def run_nmap(target, port=None):
    xml_file = "nmap_results.xml"
    port_arg = f"-p {port}" if port else ""
    print(f"[*] Running Nmap scan on {target} {f'port {port}' if port else 'common ports'} with CVE detection...")
    cmd = f"nmap -sV --script vulners -T4 {port_arg} -oX {xml_file} {target}"
    subprocess.run(cmd, shell=True, check=True)
    return xml_file

def get_exploits(service, version):
    print(f"    - Checking exploits for {service} {version}...")
    cmd = f"python3 tools/exploit_matcher.py '{service}' --version '{version}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

def create_org_report(target_full, xml_file):
    # Make filename safe by replacing dots and colons
    safe_name = target_full.replace('.', '_').replace(':', '_')
    report_path = f"notes/{safe_name}.org"
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    with open(report_path, "w") as f:
        f.write(f"#+TITLE: Recon Report: {target_full}\n")
        f.write(f"#+AUTHOR: Bughunt Master-Recon\n")
        f.write(f"#+DATE: {datetime.now().strftime('[%Y-%m-%d %a]')}\n\n")
        
        f.write("* Overview\n")
        f.write(f"- Target: {target_full}\n")
        f.write("- Status: Enumerated\n\n")
        
        f.write("* Reconnaissance\n")
        f.write("** Open Ports & Services\n")
        
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
                    
                    f.write(f"*** Port {portid}: {service_name}\n")
                    f.write(f"- Product: {product}\n")
                    f.write(f"- Version: {version}\n")
                    
                    # Add CVEs from Nmap
                    script_elem = port_elem.find(".//script[@id='vulners']")
                    if script_elem is not None:
                        f.write("- Potential CVEs:\n")
                        f.write("#+BEGIN_EXAMPLE\n")
                        f.write(script_elem.get('output'))
                        f.write("\n#+END_EXAMPLE\n")
                    
                    # Run and add Exploits
                    if product:
                        exploits = get_exploits(product, version)
                        f.write("- Exploit Matcher Output:\n")
                        f.write("#+BEGIN_EXAMPLE\n")
                        f.write(exploits)
                        f.write("#+END_EXAMPLE\n")
                    
                    # Trigger custom vulnerability tools
                    if service_name == "http" or portid in ["5002", "5003", "5004"]:
                        f.write("- Custom Tooling Findings:\n")
                        f.write("#+BEGIN_SRC bash\n")
                        f.write(f"python3 tools/verbose_checker.py http://{addr}:{portid}/FUZZ\n")
                        f.write("#+END_SRC\n")
                    f.write("\n")
                    
    print(f"[+] Report generated: {report_path}")
    return report_path

def main():
    parser = argparse.ArgumentParser(description="Master-Recon Orchestrator")
    parser.add_argument("target", help="Target IP, hostname or IP:Port")
    args = parser.parse_args()

    target = args.target
    port = None

    # Handle IP:Port notation
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
