"""SQL injection check: error-based (v1, unchanged signatures) + new
boolean-based and time-based blind techniques.

Each finding is tagged with which technique actually fired, since that's
useful to a learner trying to understand *why* sqlmap-style tools bother with
three different approaches instead of one.
"""

import time

from ..http_client import WebvClient
from ..params import InjectionPoint

# Real database error strings — only appear on actual SQL errors, not on any
# page that happens to mention the word 'sql' or 'error'.
DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql_fetch",
    "warning: mysqli_fetch",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "sqlstate[42000]",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "sqlite3.operationalerror",
    "syntax error or access violation",
    "division by zero in",
    "supplied argument is not a valid mysql",
]

# (true_suffix, false_suffix) pairs appended to a baseline value. If the page
# differs meaningfully between the "true" and "false" version but not between
# two "true" runs, the query is probably evaluating our injected condition.
BOOLEAN_PAIRS = [
    (" AND 1=1", " AND 1=2"),
    (" OR 1=1", " OR 1=2"),
]

TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",      # MySQL
    "'; WAITFOR DELAY '0:0:5'--",  # MSSQL
    "' OR pg_sleep(5)-- -",   # PostgreSQL
]

TIME_THRESHOLD_SECONDS = 4.0


def _send(client: WebvClient, point: InjectionPoint, value: str, capture: bool = False):
    if point.location == "query" or point.method == "get":
        return client.get(point.url, params={point.param: value}, capture=capture)
    data = {f: "test" for f in point.other_fields}
    data[point.param] = value
    return client.post(point.url, data=data, capture=capture)


def _error_based(client: WebvClient, point: InjectionPoint, payloads: list):
    for payload in payloads:
        res, transcript = _send(client, point, payload, capture=True)
        if res is None:
            continue
        text_lower = res.text.lower()
        for sig in DB_ERROR_SIGNATURES:
            if sig in text_lower:
                return {
                    "type": "SQL Injection",
                    "detail": f"[error-based] DB error signature '{sig}' triggered via {point.param}= with payload: {payload}",
                    "severity": "High",
                    "confidence": "High",
                    "transcript": transcript.as_dict() if transcript else None,
                }
    return None


def _boolean_based(client: WebvClient, point: InjectionPoint, baseline_value: str = "1"):
    for true_suffix, false_suffix in BOOLEAN_PAIRS:
        res_true, t_true = _send(client, point, baseline_value + true_suffix, capture=True)
        res_false, _ = _send(client, point, baseline_value + false_suffix)
        res_base, _ = _send(client, point, baseline_value)
        if not (res_true and res_false and res_base):
            continue

        same_as_base = res_true.text == res_base.text
        differs_from_false = res_true.text != res_false.text
        if same_as_base and differs_from_false:
            return {
                "type": "SQL Injection",
                "detail": (
                    f"[boolean-based blind] {point.param}='{baseline_value}{true_suffix}' matched the "
                    f"baseline response while '{baseline_value}{false_suffix}' did not — the condition "
                    "is being evaluated inside a query."
                ),
                "severity": "High",
                "confidence": "Medium",
                "transcript": t_true.as_dict() if t_true else None,
            }
    return None


def _time_based(client: WebvClient, point: InjectionPoint):
    for payload in TIME_PAYLOADS:
        start = time.monotonic()
        res, transcript = _send(client, point, payload, capture=True)
        elapsed = time.monotonic() - start
        if res is None:
            continue
        if elapsed >= TIME_THRESHOLD_SECONDS:
            return {
                "type": "SQL Injection",
                "detail": (
                    f"[time-based blind] {point.param}={payload!r} delayed the response by "
                    f"{elapsed:.1f}s — consistent with a SLEEP()-style injected query."
                ),
                "severity": "High",
                "confidence": "Medium",
                "transcript": transcript.as_dict() if transcript else None,
            }
    return None


def check_sql_point(client: WebvClient, point: InjectionPoint, payloads: list, deep: bool = False) -> list:
    finding = _error_based(client, point, payloads)
    if finding:
        return [finding]

    finding = _boolean_based(client, point)
    if finding:
        return [finding]

    # Time-based probing is slow (adds real seconds per param) — only worth it
    # in deep mode, where thoroughness is explicitly the trade-off being made.
    if deep:
        finding = _time_based(client, point)
        if finding:
            return [finding]

    return []


def check_sql(client: WebvClient, url: str, payloads: list, param: str = "id", deep: bool = False) -> list:
    """Back-compat single-param entry point."""
    point = InjectionPoint(url=url, method="get", param=param, location="query")
    return check_sql_point(client, point, payloads, deep=deep)
