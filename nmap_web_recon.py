#!/usr/bin/env python3
"""Basic nmap recon script for web application targets."""

import subprocess
import sys
import argparse
from datetime import datetime


def run_nmap(cmd: list[str], label: str) -> str:
    print(f"\n[*] {label}")
    print(f"    Command: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and result.stderr:
        print(f"[!] Warning: {result.stderr.strip()}")
    return result.stdout


def recon(target: str, output_dir: str = ".") -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{output_dir}/{target.replace('/', '_')}_{timestamp}"

    print(f"\n{'='*60}")
    print(f"  Web App Recon: {target}")
    print(f"  Started:       {datetime.now()}")
    print(f"{'='*60}")

    # 1. Quick port scan — common web ports
    out = run_nmap(
        ["nmap", "-sV", "--open", "-p", "80,443,8080,8443,8000,8888,3000,4000,5000",
         "-T4", target, "-oN", f"{base}_web_ports.txt"],
        "Web port scan (common ports)"
    )
    print(out)

    # 2. Full TCP scan to catch non-standard ports
    out = run_nmap(
        ["nmap", "-sV", "--open", "-p-", "-T4", "--min-rate", "1000",
         target, "-oN", f"{base}_full_tcp.txt"],
        "Full TCP port scan"
    )
    print(out)

    # 3. HTTP/HTTPS service detection + default scripts
    out = run_nmap(
        ["nmap", "-sV", "-sC", "-p", "80,443,8080,8443",
         target, "-oN", f"{base}_http_scripts.txt"],
        "HTTP service + default scripts"
    )
    print(out)

    # 4. Vulnerability scripts focused on web
    out = run_nmap(
        ["nmap", "--script",
         "http-headers,http-methods,http-title,http-robots.txt,"
         "http-server-header,ssl-cert,ssl-enum-ciphers",
         "-p", "80,443,8080,8443",
         target, "-oN", f"{base}_vuln_scripts.txt"],
        "Web-focused NSE scripts"
    )
    print(out)

    print(f"\n[+] Results saved to: {base}_*.txt")
    print(f"[+] Scan complete: {datetime.now()}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Basic nmap recon for web applications",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nmap_web_recon.py example.com
  python nmap_web_recon.py 192.168.1.10 -o /tmp/scans
  python nmap_web_recon.py 10.10.10.0/24
        """
    )
    parser.add_argument("target", help="Target IP, hostname, or CIDR range")
    parser.add_argument("-o", "--output", default=".", help="Output directory for results (default: .)")
    args = parser.parse_args()

    recon(args.target, args.output)


if __name__ == "__main__":
    main()
