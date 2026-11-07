import re
from urllib.parse import parse_qs, urlparse

from webv.checks.sqli import check_sql_point
from webv.http_client import WebvClient
from webv.params import InjectionPoint

PAYLOADS = ["'", "' OR 1=1 --"]


def _qs_value(handler, name, default=""):
    qs = parse_qs(urlparse(handler.path).query)
    return qs.get(name, [default])[0]


def test_sqli_error_based_detected(make_server):
    def handler(h):
        v = _qs_value(h, "id")
        if "'" in v:
            body = b"Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result"
        else:
            body = b"ok"
        h.send_response(200)
        h.end_headers()
        h.wfile.write(body)

    base = make_server({"/": handler})
    client = WebvClient()
    point = InjectionPoint(url=base + "/", method="get", param="id", location="query")
    findings = check_sql_point(client, point, PAYLOADS)
    assert len(findings) == 1
    assert "error-based" in findings[0]["detail"]


def test_sqli_boolean_based_detected(make_server):
    """A toy 'vulnerable' endpoint: it actually evaluates `id <expr>` as a
    Python boolean expression server-side (never do this in real code) so the
    boolean-based technique has a genuine signal to find."""

    def handler(h):
        v = _qs_value(h, "id")
        expr = re.sub(r"(\d)=(\d)", r"\1==\2", v).replace("AND", "and").replace("OR", "or")
        try:
            truthy = eval(expr)  # noqa: S307 - test fixture only, never do this in real code
        except Exception:
            truthy = False
        body = b"row found" if truthy else b"no rows"
        h.send_response(200)
        h.end_headers()
        h.wfile.write(body)

    base = make_server({"/": handler})
    client = WebvClient()
    point = InjectionPoint(url=base + "/", method="get", param="id", location="query")
    findings = check_sql_point(client, point, [])  # no error-based payloads configured
    assert len(findings) == 1
    assert "boolean-based" in findings[0]["detail"]


def test_sqli_no_finding_when_param_ignored(make_server):
    def handler(h):
        h.send_response(200)
        h.end_headers()
        h.wfile.write(b"always the same")

    base = make_server({"/": handler})
    client = WebvClient()
    point = InjectionPoint(url=base + "/", method="get", param="id", location="query")
    assert check_sql_point(client, point, PAYLOADS) == []
