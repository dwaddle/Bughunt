#!/usr/bin/env python3
"""
Master-Recon: The orchestrator for the Bughunt reconnaissance phase.
It runs Nmap, parses the output, and automatically triggers vulnerability-specific tools.
"""

import subprocess
import argparse
import os
import xml.etree.ElementTree as ET

def run_nmap(target):
    xml_file = "nmap_results.xml"
    print(f"[*] Running Nmap scan on {target} with CVE detection...")
    # Scan for common ports with service detection, default scripts AND vulners script
    cmd = f"nmap -sV --script vulners -T4 -oX {xml_file} {target}"
    subprocess.run(cmd, shell=True, check=True)
    return xml_file

def parse_and_scan(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    findings = []
    for host in root.findall('host'):
        addr = host.find('address').get('addr')
        for port_elem in host.findall('.//port'):
            portid = port_elem.get('portid')
            state = port_elem.find('state').get('state')
            
            if state == 'open':
                service_elem = port_elem.find('service')
                service_name = service_elem.get('name') if service_elem is not None else "unknown"
                print(f"[+] Found Open Port: {portid} ({service_name})")
                
                # Logic to trigger specific tools
                if service_name == "http" or "http" in service_name or portid in ["5002", "5003", "5004", "80", "443", "8080"]:
                    trigger_http_tools(addr, portid)

def trigger_http_tools(target, port):
    print(f"[*] Triggering HTTP vulnerability scans for {target}:{port}...")
    
    # 1. Run Verbose-Checker (Basic GET)
    verbose_cmd = f"python3 tools/verbose_checker.py http://{target}:{port}/FUZZ"
    print(f"    - Running Verbose-Checker...")
    subprocess.run(verbose_cmd, shell=True)
    
    # 2. Potential for more tools here (e.g., Hunter-SCA if endpoints are found)
    # We could also add common path discovery here (gobuster/feroxbuster)

def main():
    parser = argparse.ArgumentParser(description="Master-Recon Orchestrator")
    parser.add_argument("target", help="Target IP or hostname")
    args = parser.parse_args()

    try:
        xml_output = run_nmap(args.target)
        parse_and_scan(xml_output)
        print("\n[*] Reconnaissance phase completed.")
    except Exception as e:
        print(f"[x] Critical Error: {e}")

if __name__ == "__main__":
    main()
