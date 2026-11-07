"""Open redirect check — ported from v1, using the shared WebvClient."""

from ..http_client import WebvClient

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "goto", "redir", "destination", "target"]
TEST_PAYLOAD = "https://evil-attacker.com"


def check_open_redirect(client: WebvClient, url: str) -> list:
    for param in REDIRECT_PARAMS:
        res, _ = client.get(url, params={param: TEST_PAYLOAD}, follow_redirects=False)
        if res is None:
            continue
        location = res.headers.get("Location", "")
        if "evil-attacker.com" in location:
            return [{
                "type": "Open Redirect",
                "detail": f"Server redirects to attacker-controlled URL via ?{param}= parameter.",
                "severity": "Medium",
                "confidence": "High",
            }]
    return []
