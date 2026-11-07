"""New: inspect Set-Cookie headers for the Secure / HttpOnly / SameSite flags.

httpx exposes raw Set-Cookie header values via response.headers.get_list, so
we parse the flags ourselves rather than relying on the cookie jar (which
already stripped them).
"""


def check_cookies(response) -> list:
    findings = []
    raw_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            findings.append({
                "type": "Insecure Cookie",
                "detail": f"Cookie '{name}' is missing: {', '.join(missing)}",
                "severity": "Medium" if "HttpOnly" in missing else "Low",
                "confidence": "High",
            })
    return findings
