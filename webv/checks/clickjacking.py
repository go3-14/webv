"""New: dedicated clickjacking check.

Missing Header already flags an absent X-Frame-Options, but that's not the
full picture — a CSP frame-ancestors directive also blocks framing and should
count as protected even with no X-Frame-Options. This check looks at both
together so XFO-only sites aren't double-penalized, and CSP-only sites aren't
falsely flagged.
"""


def check_clickjacking(response) -> list:
    xfo = response.headers.get("X-Frame-Options", "")
    csp = response.headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if xfo or has_frame_ancestors:
        return []

    return [{
        "type": "Clickjacking",
        "detail": "No X-Frame-Options header and no CSP frame-ancestors directive — page can be framed.",
        "severity": "Medium",
        "confidence": "High",
    }]
