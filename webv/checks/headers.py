"""Missing security headers — ported from v1 unchanged."""

SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


def check_headers(response) -> list:
    findings = []
    for h in SECURITY_HEADERS:
        if h not in response.headers:
            findings.append({
                "type": "Missing Header",
                "detail": h,
                "severity": "Low",
                "confidence": "High",
            })
    return findings
