"""Passive/heuristic SSRF param flagger.

Deliberately does NOT attempt to reach cloud metadata endpoints or any real
internal target — that would be an active exploitation step requiring much
stronger authorization context than "the user ran a scan". Instead this
flags parameters that *look* like they might cause a server-side fetch, so a
learner knows exactly where to go investigate (and understand) manually.
"""

from ..params import InjectionPoint

SUSPICIOUS_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination", "callback",
    "webhook", "feed", "fetch", "load", "path", "continue", "file", "page",
    "proxy", "target", "redirect_uri",
}


def check_ssrf_point(point: InjectionPoint) -> list:
    if point.param.lower() in SUSPICIOUS_NAMES:
        return [{
            "type": "Potential SSRF",
            "detail": (
                f"Parameter '{point.param}' on {point.method.upper()} {point.url} has a name commonly "
                "used for server-side fetches. Not confirmed — verify manually with a controlled "
                "listener (e.g. a request-bin style endpoint you control)."
            ),
            "severity": "Low",
            "confidence": "Low",
        }]
    return []
