"""SSL/TLS checks — ported from v1 unchanged (raw socket + ssl module)."""

import logging
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

WEAK_CIPHERS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON"]


def check_ssl(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme != "https":
        findings.append({
            "type": "No HTTPS",
            "detail": "Site does not use HTTPS — all traffic is transmitted in plaintext.",
            "severity": "High",
            "confidence": "High",
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            cipher = s.cipher()

            if any(w in cipher[0] for w in WEAK_CIPHERS):
                findings.append({
                    "type": "Weak TLS Cipher",
                    "detail": f"Negotiated weak cipher suite: {cipher[0]}",
                    "severity": "High",
                    "confidence": "High",
                })

            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            if days_left < 30:
                sev = "High" if days_left < 7 else "Medium"
                findings.append({
                    "type": "SSL Certificate Expiring",
                    "detail": f"Certificate expires in {days_left} day(s) on {cert['notAfter']}.",
                    "severity": sev,
                    "confidence": "High",
                })

    except ssl.SSLCertVerificationError:
        findings.append({
            "type": "Invalid SSL Certificate",
            "detail": "Certificate verification failed — may be self-signed or untrusted CA.",
            "severity": "High",
            "confidence": "High",
        })
    except ssl.SSLError as e:
        findings.append({
            "type": "Invalid SSL Certificate",
            "detail": f"SSL handshake error: {e}",
            "severity": "Medium",
            "confidence": "Medium",
        })
    except (socket.timeout, OSError) as e:
        logging.debug("SSL check connection failed for %s: %s", hostname, e)

    return findings
