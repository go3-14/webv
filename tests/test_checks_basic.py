"""Headers / cookies / clickjacking — pure header-inspection checks."""

from webv.checks.clickjacking import check_clickjacking
from webv.checks.cookies import check_cookies
from webv.checks.headers import check_headers
from webv.http_client import WebvClient


def _plain(handler):
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html")
    handler.end_headers()
    handler.wfile.write(b"<html></html>")


def test_check_headers_flags_all_missing(make_server):
    base = make_server({"/": _plain})
    client = WebvClient()
    res, _ = client.get(base + "/")
    findings = check_headers(res)
    assert len(findings) == 5
    assert all(f["type"] == "Missing Header" for f in findings)


def test_check_headers_none_missing(make_server):
    def handler(h):
        h.send_response(200)
        for name in [
            "X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options",
            "Strict-Transport-Security", "Referrer-Policy",
        ]:
            h.send_header(name, "set")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    res, _ = client.get(base + "/")
    assert check_headers(res) == []


def test_check_cookies_flags_missing_flags(make_server):
    def handler(h):
        h.send_response(200)
        h.send_header("Set-Cookie", "session=abc123")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    res, _ = client.get(base + "/")
    findings = check_cookies(res)
    assert len(findings) == 1
    assert "Secure" in findings[0]["detail"] and "HttpOnly" in findings[0]["detail"]


def test_check_cookies_all_flags_present(make_server):
    def handler(h):
        h.send_response(200)
        h.send_header("Set-Cookie", "session=abc123; Secure; HttpOnly; SameSite=Lax")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    res, _ = client.get(base + "/")
    assert check_cookies(res) == []


def test_check_clickjacking_flags_when_unprotected(make_server):
    base = make_server({"/": _plain})
    client = WebvClient()
    res, _ = client.get(base + "/")
    findings = check_clickjacking(res)
    assert len(findings) == 1
    assert findings[0]["type"] == "Clickjacking"


def test_check_clickjacking_not_flagged_with_xfo(make_server):
    def handler(h):
        h.send_response(200)
        h.send_header("X-Frame-Options", "DENY")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    res, _ = client.get(base + "/")
    assert check_clickjacking(res) == []
