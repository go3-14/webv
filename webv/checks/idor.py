"""Conservative IDOR heuristic.

Only runs when:
  - the scan is authenticated (client.authenticated is True), and
  - the user explicitly opted in via --enable-idor (idor.py itself does not
    enforce this — the caller in cli.py / run_scan does, so the gate is
    visible in one obvious place).

This swaps a numeric ID found in the URL/param for an adjacent value and
diffs the two *authenticated* responses. A real IDOR needs the second
response to belong to a different, unauthorized resource — this heuristic
cannot prove that on its own, so it's reported at Low confidence as
"needs manual confirmation", never as a settled finding.
"""

import re

from ..http_client import WebvClient
from ..params import InjectionPoint

_NUMERIC_RE = re.compile(r"^\d+$")


def check_idor_point(client: WebvClient, point: InjectionPoint) -> list:
    if not _NUMERIC_RE.match(point.param) and point.location == "query":
        return []

    # We only meaningfully probe numeric *values*, not arbitrary param names.
    # Try the param's current value if it's numeric; otherwise skip.
    return []  # placeholder for value-based probing wired in from run_scan,
    # where the actual current value (needed to compute "adjacent") is known.


def check_idor_value(client: WebvClient, url: str, method: str, param: str,
                      current_value: str, other_fields: dict | None = None) -> list:
    if not current_value.isdigit():
        return []

    adjacent = str(int(current_value) + 1)
    other_fields = other_fields or {}

    def fetch(value):
        if method == "get":
            return client.get(url, params={**other_fields, param: value})
        data = dict(other_fields)
        data[param] = value
        return client.post(url, data=data)

    res_current, _ = fetch(current_value)
    res_adjacent, _ = fetch(adjacent)
    if res_current is None or res_adjacent is None:
        return []

    if res_adjacent.status_code == 200 and res_adjacent.text != res_current.text:
        return [{
            "type": "Potential IDOR",
            "detail": (
                f"Authenticated request to {param}={adjacent} (adjacent to your own ID "
                f"{current_value}) returned a different HTTP 200 response. Manually confirm "
                "this is actually another user's data before treating it as confirmed."
            ),
            "severity": "Medium",
            "confidence": "Low",
        }]
    return []
