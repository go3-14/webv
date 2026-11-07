"""Context-aware reflected XSS check.

v1 only ever tried one payload against ?q= and called any unescaped
reflection "High". That misses a lot (a payload that lands inside an
attribute needs a different shape to actually execute) and under-explains
*why* a hit is exploitable.

This version:
  1. Sends a random marker as the value to see *where* it lands in the
     response (HTML body text / inside a tag attribute / inside a <script>
     block) — same idea as professional scanners' "context probing".
  2. Picks a payload shaped for that context (falls back to the user's
     configured payloads.json list as the base building block).
  3. Confirms the payload reflects unescaped (same check as v1: payload
     present, html.escape(payload) absent) before reporting.
"""

import html as _html
import random
import re
import string

from ..http_client import WebvClient
from ..params import InjectionPoint

_SCRIPT_TAG_RE = re.compile(r"<script\b", re.IGNORECASE)
_SCRIPT_CLOSE_RE = re.compile(r"</script", re.IGNORECASE)


def _random_marker() -> str:
    return "wv" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _classify_context(text: str, marker: str) -> str | None:
    idx = text.find(marker)
    if idx == -1:
        return None
    before = text[max(0, idx - 300):idx]

    last_open = before.lower().rfind("<script")
    last_close = before.lower().rfind("</script")
    if last_open != -1 and last_open > last_close:
        return "script"

    tail = before[-3:]
    if tail.endswith('="') or tail.endswith("='"):
        return "attribute"

    return "body"


def _payload_for_context(context: str, base_payload: str) -> str:
    if context == "attribute":
        return f"\" onmouseover=alert(1) x=\"{base_payload}"
    if context == "script":
        return f"';alert(1);//{base_payload}"
    return base_payload  # "body" and unknown contexts: the payload as-is


def _send(client: WebvClient, point: InjectionPoint, value: str, capture: bool = False):
    if point.location == "query" or point.method == "get":
        return client.get(point.url, params={point.param: value}, capture=capture)
    data = {f: "test" for f in point.other_fields}
    data[point.param] = value
    return client.post(point.url, data=data, capture=capture)


def check_xss_point(client: WebvClient, point: InjectionPoint, base_payloads: list) -> list:
    marker = _random_marker()
    probe_res, _ = _send(client, point, marker)
    if probe_res is None:
        return []

    context = _classify_context(probe_res.text, marker)
    if context is None:
        return []  # marker never reflected at all — not injectable here

    findings = []
    for base_payload in base_payloads:
        payload = _payload_for_context(context, base_payload)
        res, transcript = _send(client, point, payload, capture=True)
        if res is None:
            continue
        escaped = _html.escape(payload)
        if payload in res.text and escaped not in res.text:
            findings.append({
                "type": "XSS",
                "detail": (
                    f"Unescaped payload reflected via {point.method.upper()} "
                    f"{point.param}= (context: {context}): {payload}"
                ),
                "severity": "High" if context in ("attribute", "script") else "Medium",
                "confidence": "High",
                "transcript": transcript.as_dict() if transcript else None,
            })
            break  # one confirmed hit per injection point is enough
    return findings


def check_xss(client: WebvClient, url: str, base_payloads: list, param: str = "q") -> list:
    """Back-compat single-param entry point, used for the base URL before a
    full crawl has produced InjectionPoints."""
    point = InjectionPoint(url=url, method="get", param=param, location="query")
    return check_xss_point(client, point, base_payloads)
