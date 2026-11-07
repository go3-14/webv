"""Nmap integration — ported from v1 unchanged."""

import logging
import subprocess


def run_nmap(host: str) -> str:
    try:
        res = subprocess.run(
            ["nmap", "-F", host],
            capture_output=True, text=True, timeout=60,
        )
        return res.stdout
    except FileNotFoundError:
        logging.error("Nmap is not installed or not on PATH.")
        return ""
    except subprocess.TimeoutExpired:
        logging.warning("Nmap scan timed out after 60 seconds.")
        return ""
    except subprocess.SubprocessError as e:
        logging.error("Nmap failed: %s", e)
        return ""


def parse_nmap(output: str) -> list:
    findings = []
    for line in output.split("\n"):
        if "open" in line and "/tcp" in line:
            findings.append({
                "type": "Open Port",
                "detail": line.strip(),
                "severity": "Medium",
                "confidence": "High",
            })
    return findings
