"""Nikto integration — ported from v1 unchanged."""

import logging
import subprocess


def run_nikto(url: str) -> str:
    try:
        res = subprocess.run(
            ["nikto", "-h", url, "-maxtime", "20"],
            capture_output=True, text=True, timeout=60,
        )
        return res.stdout
    except FileNotFoundError:
        logging.error("Nikto is not installed or not on PATH.")
        return ""
    except subprocess.TimeoutExpired:
        logging.warning("Nikto scan timed out after 60 seconds.")
        return ""
    except subprocess.SubprocessError as e:
        logging.error("Nikto failed: %s", e)
        return ""


def parse_nikto(output: str) -> list:
    findings = []
    for line in output.split("\n"):
        if line.startswith("+ ") and len(line) > 3:
            findings.append({
                "type": "Nikto Finding",
                "detail": line.strip(),
                "severity": "Medium",
                "confidence": "Low",
            })
    return findings
