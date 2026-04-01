#!/usr/bin/env python3

import requests
import subprocess
import sys
from urllib.parse import urlparse


VULN_INFO = {
    "Missing X-Frame-Options": {
        "description": "Prevents clickjacking attacks.",
        "risk": "Attackers can embed your site in an iframe.",
        "fix": "Set X-Frame-Options: DENY or SAMEORIGIN"
    },
    "Missing Content-Security-Policy": {
        "description": "Protects against XSS.",
        "risk": "Malicious scripts may execute.",
        "fix": "Define CSP header"
    },
    "Missing X-Content-Type-Options": {
        "description": "Prevents MIME sniffing.",
        "risk": "Browser may misinterpret files.",
        "fix": "Set nosniff"
    },
    "XSS": {
        "description": "Cross-Site Scripting vulnerability.",
        "risk": "Session hijacking or script injection.",
        "fix": "Sanitize input"
    },
    "SQL Injection": {
        "description": "Database query injection.",
        "risk": "Data breach or bypass auth.",
        "fix": "Use prepared statements"
    },
    "Open Port": {
        "description": "Exposed service.",
        "risk": "Attack surface increases.",
        "fix": "Close unused ports"
    },
    "Nikto Finding": {
        "description": "Server misconfiguration.",
        "risk": "May expose sensitive info.",
        "fix": "Update and secure server"
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
# Internal Checks
# -----------------------------
def check_headers(response):
    issues = []
    h = response.headers

    if "X-Frame-Options" not in h:
        issues.append("Missing X-Frame-Options")
    if "Content-Security-Policy" not in h:
        issues.append("Missing Content-Security-Policy")
    if "X-Content-Type-Options" not in h:
        issues.append("Missing X-Content-Type-Options")

    return issues


def check_xss(url):
    payload = "<script>alert(1)</script>"
    try:
        r = requests.get(f"{url}?q={payload}")
        return payload in r.text
    except:
        return False


def check_sql(url):
    try:
        r = requests.get(f"{url}?id='")
        return any(x in r.text.lower() for x in ["sql", "error"])
    except:
        return False


# -----------------------------
# Nikto
# -----------------------------
def classify_nikto(line):
    l = line.lower()
    if "xss" in l:
        return "XSS", "High"
    elif "sql" in l:
        return "SQL Injection", "High"
    elif "header" in l:
        return "Missing Security Header", "Low"
    elif "cookie" in l:
        return "Nikto Finding", "Medium"
    else:
        return "Nikto Finding", "Medium"


def run_nikto(url):
    try:
        r = subprocess.run(["nikto", "-h", url], capture_output=True, text=True)
        return r.stdout
    except:
        return ""


def parse_nikto(output):
    findings = []
    for line in output.split("\n"):
        if "+ " in line:
            t, s = classify_nikto(line)
            findings.append({"type": t, "detail": line.strip(), "severity": s})
    return findings


# -----------------------------
# Nmap
# -----------------------------
def run_nmap(host):
    try:
        r = subprocess.run(["nmap", "-F", host], capture_output=True, text=True)
        return r.stdout
    except:
        return ""


def parse_nmap(output):
    findings = []
    for line in output.split("\n"):
        if "open" in line:
            findings.append({
                "type": "Open Port",
                "detail": line.strip(),
                "severity": "Medium"
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
def generate_report(vulns, url):
    high = sum(1 for v in vulns if v["severity"] == "High")
    med = sum(1 for v in vulns if v["severity"] == "Medium")
    low = sum(1 for v in vulns if v["severity"] == "Low")

    risk = overall_risk(vulns)

    with open("report.html", "w") as f:
        f.write(f"""
<html>
<head>
<title>Report</title>
<style>
body {{ font-family: Arial; background:#f4f4f4; }}
.card {{ background:white; padding:10px; margin:10px; border-radius:5px; }}
.high {{ color:red; }}
.medium {{ color:orange; }}
.low {{ color:green; }}
.bar {{
  display:flex;
  height:20px;
}}
.bar div {{
  height:100%;
}}
</style>
</head>

<body>

<h1>Vulnerability Report</h1>
<p><b>Target:</b> {url}</p>

<h2>Overall Risk: <span class="{risk.lower()}">{risk}</span></h2>

<h2>Severity Distribution</h2>

<div class="bar">
  <div style="width:{high*10}px; background:red;"></div>
  <div style="width:{med*10}px; background:orange;"></div>
  <div style="width:{low*10}px; background:green;"></div>
</div>

<p>High: {high} | Medium: {med} | Low: {low}</p>

<h2>Findings</h2>
""")

        for v in vulns:
            info = VULN_INFO.get(v["type"], {})

            f.write(f"""
<div class="card">
<h3 class="{v['severity'].lower()}">{v['type']}</h3>
<p><b>Details:</b> {v['detail']}</p>
<p><b>Description:</b> {info.get('description','N/A')}</p>
<p><b>Risk:</b> {info.get('risk','N/A')}</p>
<p><b>Fix:</b> {info.get('fix','N/A')}</p>
<p><b>Severity:</b> {v['severity']}</p>
</div>
""")

        f.write("</body></html>")


# -----------------------------
# MAIN
# -----------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: checker <url>")
        return

    url = sys.argv[1]

    print(f"[+] Scanning {url}")

    r = validate_url(url)
    if not r:
        print("[-] Invalid URL")
        return

    vulns = []

    for h in check_headers(r):
        vulns.append({"type": h, "detail": h, "severity": "Low"})

    if check_xss(url):
        vulns.append({"type": "XSS", "detail": "Reflected payload", "severity": "High"})

    if check_sql(url):
        vulns.append({"type": "SQL Injection", "detail": "DB error", "severity": "High"})

    print("[+] Running Nikto...")
    vulns.extend(parse_nikto(run_nikto(url)))

    print("[+] Running Nmap...")
    vulns.extend(parse_nmap(run_nmap(extract_host(url))))

    print(f"[+] Found {len(vulns)} issues")

    generate_report(vulns, url)

    print("[+] Report generated: report.html")


if __name__ == "__main__":
    main()