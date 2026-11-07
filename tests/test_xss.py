from urllib.parse import parse_qs, urlparse

from webv.checks.xss import check_xss_point
from webv.http_client import WebvClient
from webv.params import InjectionPoint

PAYLOADS = ["<script>alert(1)</script>"]


def _qs_value(handler, name, default=""):
    qs = parse_qs(urlparse(handler.path).query)
    return qs.get(name, [default])[0]


def test_xss_detected_in_body_context(make_server):
    def handler(h):
        q = _qs_value(h, "q")
        body = f"<html><body><p>{q}</p></body></html>".encode()
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(body)

    base = make_server({"/": handler})
    client = WebvClient()
    point = InjectionPoint(url=base + "/", method="get", param="q", location="query")
    findings = check_xss_point(client, point, PAYLOADS)
    assert len(findings) == 1
    assert "body" in findings[0]["detail"]


def test_xss_not_flagged_when_escaped(make_server):
    import html as _html

    def handler(h):
        q = _html.escape(_qs_value(h, "q"))
        body = f"<html><body><p>{q}</p></body></html>".encode()
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(body)

    base = make_server({"/": handler})
    client = WebvClient()
    point = InjectionPoint(url=base + "/", method="get", param="q", location="query")
    assert check_xss_point(client, point, PAYLOADS) == []


def test_xss_not_flagged_when_never_reflected(make_server):
    def handler(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>static page</body></html>")

    base = make_server({"/": handler})
    client = WebvClient()
    point = InjectionPoint(url=base + "/", method="get", param="q", location="query")
    assert check_xss_point(client, point, PAYLOADS) == []
