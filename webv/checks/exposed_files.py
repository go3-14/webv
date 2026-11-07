"""New: probe for commonly-exposed sensitive files and directory listings.

Deliberately read-only (GET only, no modification attempts) and limited to a
short, well-known list — this is reconnaissance, not a full path brute-forcer.
"""

import re

from ..http_client import WebvClient

SENSITIVE_PATHS = {
    ".git/config": "[core]",
    ".git/HEAD": "ref:",
    ".env": "=",
    ".DS_Store": None,
    "backup.zip": None,
    "backup.sql": None,
    "wp-config.php.bak": None,
    ".htpasswd": None,
    "config.php.bak": None,
}

_DIR_LISTING_RE = re.compile(r"<title>Index of /|Directory listing for /", re.IGNORECASE)


def check_exposed_files(client: WebvClient, base_url: str) -> list:
    findings = []
    base = base_url.rstrip("/")

    for path, signature in SENSITIVE_PATHS.items():
        res, _ = client.get(f"{base}/{path}")
        if res is None or res.status_code != 200:
            continue
        if signature is None or signature in res.text[:4000]:
            findings.append({
                "type": "Exposed Sensitive File",
                "detail": f"Publicly reachable: /{path} (HTTP 200)",
                "severity": "High",
                "confidence": "Medium",
            })

    res, _ = client.get(base + "/")
    if res is not None and _DIR_LISTING_RE.search(res.text[:2000]):
        findings.append({
            "type": "Directory Listing",
            "detail": "Root path returns a browsable directory index.",
            "severity": "Low",
            "confidence": "High",
        })

    return findings
