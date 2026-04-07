#!/usr/bin/env python3

import requests
import subprocess
import sys
import time
import random
import json
import argparse
from urllib.parse import urlparse
from bs4 import BeautifulSoup


PAYLOAD_FILE = "payloads.json"

import shutil

def check_dependencies():
    missing = []

    if not shutil.which("nmap"):
        missing.append("nmap")

    if not shutil.which("nikto"):
        missing.append("nikto")

    if missing:
        print("\n[!] Missing tools:")
        for m in missing:
            print(f" - {m}")

        print("\nInstall using:")
        print("sudo apt install " + " ".join(missing))
        return False

    return True

# -----------------------------
# Banner
# -----------------------------
def print_banner():
    banner = r"""
██╗    ██╗███████╗██████╗ ██╗   ██╗
██║    ██║██╔════╝██╔══██╗██║   ██║
██║ █╗ ██║█████╗  ██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝

   Web Vulnerability Scanner (webv)
"""
    print(banner)


# -----------------------------
# Payload Handling
# -----------------------------
def load_payloads():
    try:
        with open(PAYLOAD_FILE, "r") as f:
            return json.load(f)
    except:
        return {"xss": ["<script>alert(1)</script>"], "sqli": ["'"]}


def save_payloads(data):
    with open(PAYLOAD_FILE, "w") as f:
        json.dump(data, f, indent=4)


# -----------------------------
# Knowledge Base
# -----------------------------
VULN_INFO = {
    "XSS": {
        "description": "Script injection vulnerability.",
        "risk": "Session hijacking or data theft.",
        "fix": "Sanitize inputs"
    },
    "SQL Injection": {
        "description": "Database query manipulation.",
        "risk": "Data breach or auth bypass.",
        "fix": "Use prepared statements"
    },
    "Missing Header": {
        "description": "Missing security headers.",
        "risk": "Weak protection.",
        "fix": "Add HTTP security headers"
    },
    "Open Port": {
        "description": "Exposed service.",
        "risk": "Potential attack surface.",
        "fix": "Close unused ports"
    },
    "Nikto Finding": {
        "description": "Server misconfiguration.",
        "risk": "Potential vulnerabilities.",
        "fix": "Update server"
    }
}


# -----------------------------
# Helpers
# -----------------------------
def extract_host(url):
    return urlparse(url).netloc


def validate_url(url):
    try:
        return requests.get(url, timeout=5)
    except:
        return None


# -----------------------------
# Checks
# -----------------------------
def check_headers(response):
    issues = []
    for h in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
        if h not in response.headers:
            issues.append(h)
    return issues


def check_xss(url):
    payloads = load_payloads()["xss"]

    for payload in payloads:
        try:
            res = requests.get(f"{url}?q={payload}")
            if payload in res.text:
                return {
                    "detail": f"Payload reflected: {payload}",
                    "severity": "High",
                    "confidence": "Medium"
                }
        except:
            pass
    return None


def check_sql(url):
    payloads = load_payloads()["sqli"]

    for payload in payloads:
        try:
            res = requests.get(f"{url}?id={payload}")
            if any(x in res.text.lower() for x in ["sql", "mysql", "error"]):
                return {
                    "detail": f"Triggered with payload: {payload}",
                    "severity": "High",
                    "confidence": "High"
                }
        except:
            pass
    return None


# -----------------------------
# Endpoint Discovery
# -----------------------------
def find_links(response, base_url):
    links = []

    try:
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a"):
            href = tag.get("href")

            if href and href.startswith("/"):
                full_url = base_url.rstrip("/") + href
                links.append(full_url)

    except:
        pass

    return list(set(links))[:5]


# -----------------------------
# Nikto
# -----------------------------
def run_nikto(url):
    try:
        res = subprocess.run(
            ["nikto", "-h", url, "-maxtime", "20"],
            capture_output=True,
            text=True
        )
        return res.stdout
    except:
        return ""


def parse_nikto(output):
    findings = []
    for line in output.split("\n"):
        if "+ " in line:
            findings.append({
                "type": "Nikto Finding",
                "detail": line.strip(),
                "severity": "Medium",
                "confidence": "Low"
            })
    return findings


# -----------------------------
# Nmap (STABLE VERSION)
# -----------------------------
def run_nmap(host):
    try:
        res = subprocess.run(
            ["nmap", "-F", host],
            capture_output=True,
            text=True
        )
        return res.stdout
    except:
        return ""


def parse_nmap(output):
    findings = []
    for line in output.split("\n"):
        if "open" in line:
            findings.append({
                "type": "Open Port",
                "detail": line.strip(),
                "severity": "Medium",
                "confidence": "High"
            })
    return findings


# -----------------------------
# Risk
# -----------------------------
def overall_risk(v):
    if any(x["severity"] == "High" for x in v):
        return "High"
    elif any(x["severity"] == "Medium" for x in v):
        return "Medium"
    return "Low"


# -----------------------------
# Report
# -----------------------------
def generate_report(vulns, url, mode, endpoints):
    high = sum(1 for v in vulns if v["severity"] == "High")
    med = sum(1 for v in vulns if v["severity"] == "Medium")
    low = sum(1 for v in vulns if v["severity"] == "Low")

    risk = overall_risk(vulns)
    filename = f"report_{random.randint(1000,9999)}.html"

    with open(filename, "w") as f:
        f.write(f"""
<!DOCTYPE html>
<html>
<head>
<title>WebV Report</title>

<style>
body {{
    font-family: 'Segoe UI', sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    margin: 0;
}}

.header {{
    background: #1e293b;
    padding: 20px;
    text-align: center;
}}

.container {{
    padding: 20px;
}}

.card {{
    background: #1e293b;
    padding: 15px;
    margin: 15px 0;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.3);
}}

.badge {{
    padding: 5px 10px;
    border-radius: 5px;
    font-weight: bold;
}}

.high {{ background: #ef4444; }}
.medium {{ background: #f59e0b; }}
.low {{ background: #22c55e; }}

.summary {{
    display: flex;
    gap: 20px;
}}

.box {{
    flex: 1;
    padding: 15px;
    border-radius: 10px;
    text-align: center;
}}

.box.high {{ background: #7f1d1d; }}
.box.medium {{ background: #78350f; }}
.box.low {{ background: #14532d; }}

ul {{
    line-height: 1.8;
}}

</style>

</head>

<body>

<div class="header">
    <h1>Web Vulnerability Report</h1>
    <p><b>Target:</b> {url}</p>
    <p><b>Scan Mode:</b> {mode}</p>
    <h2>Overall Risk: <span class="badge {risk.lower()}">{risk}</span></h2>
</div>

<div class="container">

<h2>Summary</h2>
<div class="summary">
    <div class="box high">High<br>{high}</div>
    <div class="box medium">Medium<br>{med}</div>
    <div class="box low">Low<br>{low}</div>
</div>

<h2>Discovered Endpoints</h2>
<div class="card">
<ul>
""")

        for ep in endpoints:
            f.write(f"<li>{ep}</li>")

        f.write("""
</ul>
</div>

<h2>Findings</h2>
""")

        for v in vulns:
            info = VULN_INFO.get(v["type"], {})

            f.write(f"""
<div class="card">
    <h3>{v['type']} <span class="badge {v['severity'].lower()}">{v['severity']}</span></h3>
    <p><b>Details:</b> {v['detail']}</p>
    <p><b>Description:</b> {info.get('description','N/A')}</p>
    <p><b>Risk:</b> {info.get('risk','N/A')}</p>
    <p><b>Fix:</b> {info.get('fix','N/A')}</p>
    <p><b>Confidence:</b> {v['confidence']}</p>
</div>
""")

        f.write("""
</div>
</body>
</html>
""")

    return filename
# -----------------------------
# Scan Logic
# -----------------------------
def run_scan(url, fast=False, deep=False):
    if not check_dependencies():
        return
    print(f"[+] Scanning {url}")

    response = validate_url(url)
    if not response:
        print("[-] Invalid URL")
        return

    vulns = []
    discovered = []

    for h in check_headers(response):
        vulns.append({
            "type": "Missing Header",
            "detail": h,
            "severity": "Low",
            "confidence": "High"
        })

    xss = check_xss(url)
    if xss:
        vulns.append({"type": "XSS", **xss})

    sql = check_sql(url)
    if sql:
        vulns.append({"type": "SQL Injection", **sql})

    if fast:
        print("[+] Fast mode → skipping heavy scans")

    elif deep:
        print("[+] Deep mode → crawling endpoints")

        links = find_links(response, url)

        for link in links:
            print(f"[+] Scanning endpoint: {link}")
            discovered.append(link)

            time.sleep(1)

            xss = check_xss(link)
            if xss:
                vulns.append({"type": "XSS", **xss})

            sql = check_sql(link)
            if sql:
                vulns.append({"type": "SQL Injection", **sql})

        print("[+] Running Nikto...")
        vulns.extend(parse_nikto(run_nikto(url)))

        print("[+] Running Nmap...")
        vulns.extend(parse_nmap(run_nmap(extract_host(url))))

    else:
        print("[+] Normal mode")

        print("[+] Running Nikto...")
        vulns.extend(parse_nikto(run_nikto(url)))

    mode = "FAST" if fast else "DEEP" if deep else "NORMAL"
    report = generate_report(vulns, url, mode, discovered)

    print(f"[+] Report generated: {report}")


# -----------------------------
# CLI Commands
# -----------------------------
def add_payload(vtype, payload):
    data = load_payloads()

    if vtype not in data:
        print("Use xss or sqli")
        return

    data[vtype].append(payload)
    save_payloads(data)

    print("[+] Payload added")


def list_payloads():
    data = load_payloads()
    for k, v in data.items():
        print(f"\n{k.upper()}:")
        for p in v:
            print(f"- {p}")


# -----------------------------
# MAIN CLI
# -----------------------------
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Vulnerability Checker CLI")

    parser.add_argument("command", help="scan / add / list")
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("--type", help="xss or sqli")
    parser.add_argument("--payload", help="Payload to add")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--deep", action="store_true")

    args = parser.parse_args()

    if args.fast and args.deep:
        print("Choose either --fast or --deep")
        return

    if args.command == "scan":
        if not args.target:
            print("Usage: scan <url>")
            return
        run_scan(args.target, fast=args.fast, deep=args.deep)

    elif args.command == "add":
        add_payload(args.type, args.payload)

    elif args.command == "list":
        list_payloads()

    else:
        print("Invalid command")


if __name__ == "__main__":
    main()