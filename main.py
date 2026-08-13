#!/usr/bin/env python3

import requests
import subprocess
import sys
import time
import random
import json
import argparse
import logging
import shutil
from urllib.parse import urlparse
from bs4 import BeautifulSoup


PAYLOAD_FILE = "payloads.json"


# -----------------------------
# Payload Handling
# -----------------------------
def load_payloads():
    try:
        with open(PAYLOAD_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Payload file '{PAYLOAD_FILE}' not found. Using defaults.")
        return {"xss": ["<script>alert(1)</script>"], "sqli": ["'"]}
    except json.JSONDecodeError as e:
        print(f"[!] Payload file is malformed JSON: {e}. Using defaults.")
        return {"xss": ["<script>alert(1)</script>"], "sqli": ["'"]}


def save_payloads(data):
    try:
        with open(PAYLOAD_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except OSError as e:
        print(f"[!] Could not save payloads: {e}")


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


def extract_host(url):
    return urlparse(url).netloc


def validate_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        print(f"[-] Invalid URL scheme '{parsed.scheme}'. Use http:// or https://")
        return None
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        print(f"[-] Connection timed out reaching: {url}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[-] Cannot connect to: {url}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[!] HTTP {e.response.status_code} received from {url} — continuing scan.")
        return e.response
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return None


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
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(banner)


# -----------------------------
# Checks
# -----------------------------
def check_headers(response):
    issues = []
    for h in ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options"]:
        if h not in response.headers:
            issues.append(h)
    return issues


def check_xss(url, param="q"):
    """
    Check for reflected XSS. Only flags the payload if it appears *unescaped*
    in the response — avoids false positives where the server correctly
    HTML-encodes output (e.g. &lt;script&gt; is safe, <script> is not).
    Returns a list so multiple payloads can be reported.
    """
    payloads = load_payloads()["xss"]
    import html as _html
    results = []
    for payload in payloads:
        try:
            res = requests.get(url, params={param: payload}, timeout=10)
            escaped = _html.escape(payload)
            if payload in res.text and escaped not in res.text:
                results.append({
                    "type": "XSS",
                    "detail": f"Unescaped payload reflected via ?{param}=: {payload}",
                    "severity": "High",
                    "confidence": "High"
                })
        except requests.exceptions.RequestException:
            pass
    return results


# Real database error strings — only appear on actual SQL errors,
# not on any page that happens to mention the word 'sql' or 'error'.
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch",
    "warning: mysqli_fetch",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "sqlstate[42000]",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "sqlite3.operationalerror",
    "syntax error or access violation",
    "division by zero in",
    "supplied argument is not a valid mysql",
]


def check_sql(url, param="id"):
    """
    Check for SQL injection using real DB error signatures.
    Avoids false positives from pages that merely mention 'sql' or 'error'
    in their content or documentation.
    """
    payloads = load_payloads()["sqli"]
    for payload in payloads:
        try:
            res = requests.get(url, params={param: payload}, timeout=10)
            text_lower = res.text.lower()
            for sig in DB_ERROR_SIGNATURES:
                if sig in text_lower:
                    return {
                        "type": "SQL Injection",
                        "detail": f"DB error signature '{sig}' triggered via ?{param}= with payload: {payload}",
                        "severity": "High",
                        "confidence": "High"
                    }
        except requests.exceptions.RequestException:
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
    except Exception as e:
        print(f"[!] Link extraction failed: {e}")
    return list(set(links))[:5]


# -----------------------------
# Nikto
# -----------------------------
def run_nikto(url):
    try:
        res = subprocess.run(
            ["nikto", "-h", url, "-maxtime", "20"],
            capture_output=True,
            text=True,
            timeout=60
        )
        return res.stdout
    except FileNotFoundError:
        print("[-] Nikto is not installed or not on PATH.")
        return ""
    except subprocess.TimeoutExpired:
        print("[!] Nikto scan timed out.")
        return ""
    except subprocess.SubprocessError as e:
        print(f"[-] Nikto failed: {e}")
        return ""


def parse_nikto(output):
    findings = []
    for line in output.split("\n"):
        if line.startswith("+ ") and len(line) > 3:
            findings.append({
                "type": "Nikto Finding",
                "detail": line.strip(),
                "severity": "Medium",
                "confidence": "Low"
            })
    return findings


# -----------------------------
# Nmap
# -----------------------------
def run_nmap(host):
    try:
        res = subprocess.run(
            ["nmap", "-F", host],
            capture_output=True,
            text=True,
            timeout=60
        )
        return res.stdout
    except FileNotFoundError:
        print("[-] Nmap is not installed or not on PATH.")
        return ""
    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out.")
        return ""
    except subprocess.SubprocessError as e:
        print(f"[-] Nmap failed: {e}")
        return ""


def parse_nmap(output):
    findings = []
    for line in output.split("\n"):
        if "open" in line and "/tcp" in line:
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
    import html as _html
    high = sum(1 for v in vulns if v["severity"] == "High")
    med  = sum(1 for v in vulns if v["severity"] == "Medium")
    low  = sum(1 for v in vulns if v["severity"] == "Low")

    risk = overall_risk(vulns)
    # Use a timestamp instead of random int — unique, sortable, human-readable
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.html"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebV Report — {_html.escape(url)}</title>
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
    border-bottom: 2px solid #334155;
}}
.container {{
    padding: 20px;
    max-width: 960px;
    margin: 0 auto;
}}
.card {{
    background: #1e293b;
    padding: 15px;
    margin: 15px 0;
    border-radius: 10px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.3);
    border-left: 4px solid #475569;
}}
.card.high   {{ border-left-color: #ef4444; }}
.card.medium {{ border-left-color: #f59e0b; }}
.card.low    {{ border-left-color: #22c55e; }}
.badge {{
    padding: 3px 10px;
    border-radius: 5px;
    font-weight: bold;
    font-size: 0.85em;
}}
.high   {{ background: #ef4444; }}
.medium {{ background: #f59e0b; color: #000; }}
.low    {{ background: #22c55e; color: #000; }}
.summary {{
    display: flex;
    gap: 20px;
    margin-bottom: 20px;
}}
.box {{
    flex: 1;
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    font-size: 1.4em;
    font-weight: bold;
}}
.box.high   {{ background: #7f1d1d; }}
.box.medium {{ background: #78350f; }}
.box.low    {{ background: #14532d; }}
ul {{ line-height: 1.8; }}
code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="header">
    <h1>&#128269; Web Vulnerability Report</h1>
    <p><b>Target:</b> <code>{_html.escape(url)}</code></p>
    <p><b>Scan Mode:</b> {_html.escape(mode)}</p>
    <p><b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <h2>Overall Risk: <span class="badge {risk.lower()}">{_html.escape(risk)}</span></h2>
</div>
<div class="container">
<h2>Summary</h2>
<div class="summary">
    <div class="box high">High<br>{high}</div>
    <div class="box medium">Medium<br>{med}</div>
    <div class="box low">Low<br>{low}</div>
</div>
""")
        if endpoints:
            f.write("<h2>Discovered Endpoints</h2>\n<div class=\"card\">\n<ul>\n")
            for ep in endpoints:
                # html.escape prevents injected URLs from breaking the report
                f.write(f"<li><code>{_html.escape(ep)}</code></li>\n")
            f.write("</ul>\n</div>\n")

        f.write("<h2>Findings</h2>\n")
        if not vulns:
            f.write("<div class=\"card\"><p>&#10003; No vulnerabilities detected.</p></div>\n")
        else:
            for v in vulns:
                info = VULN_INFO.get(v["type"], {})
                sev_class = v["severity"].lower()
                # Every dynamic value is escaped — prevents XSS in the report itself
                f.write(f"""
<div class="card {sev_class}">
    <h3>{_html.escape(v['type'])} <span class="badge {sev_class}">{_html.escape(v['severity'])}</span></h3>
    <p><b>Details:</b> {_html.escape(v['detail'])}</p>
    <p><b>Description:</b> {_html.escape(info.get('description', 'N/A'))}</p>
    <p><b>Risk:</b> {_html.escape(info.get('risk', 'N/A'))}</p>
    <p><b>Fix:</b> {_html.escape(info.get('fix', 'N/A'))}</p>
    <p><b>Confidence:</b> {_html.escape(v.get('confidence', 'N/A'))}</p>
</div>
""")

        f.write("</div>\n</body>\n</html>\n")
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

    vulns.extend(check_xss(url))

    sql = check_sql(url)
    if sql:
        vulns.append(sql)

    if fast:
        print("[+] Fast mode → skipping heavy scans")

    elif deep:
        print("[+] Deep mode → crawling endpoints")

        links = find_links(response, url)

        for link in links:
            print(f"[+] Scanning endpoint: {link}")
            discovered.append(link)
            time.sleep(1)

            vulns.extend(check_xss(link))

            sql = check_sql(link)
            if sql:
                vulns.append(sql)

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