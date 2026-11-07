from webv.checks.cors import check_cors
from webv.checks.redirect import check_open_redirect
from webv.http_client import WebvClient


def test_cors_wildcard_flagged(make_server):
    def handler(h):
        h.send_response(200)
        h.send_header("Access-Control-Allow-Origin", "*")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    findings = check_cors(client, base + "/")
    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"


def test_cors_reflected_with_credentials_is_high(make_server):
    def handler(h):
        origin = h.headers.get("Origin", "")
        h.send_response(200)
        h.send_header("Access-Control-Allow-Origin", origin)
        h.send_header("Access-Control-Allow-Credentials", "true")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    findings = check_cors(client, base + "/")
    assert len(findings) == 1
    assert findings[0]["severity"] == "High"


def test_cors_safe_config_no_finding(make_server):
    def handler(h):
        h.send_response(200)
        h.send_header("Access-Control-Allow-Origin", "https://trusted.example.com")
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    assert check_cors(client, base + "/") == []


def test_open_redirect_detected(make_server):
    def handler(h):
        if "redirect=" in h.path:
            h.send_response(302)
            h.send_header("Location", "https://evil-attacker.com")
            h.end_headers()
        else:
            h.send_response(200)
            h.end_headers()
            h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    findings = check_open_redirect(client, base + "/")
    assert len(findings) == 1
    assert findings[0]["type"] == "Open Redirect"


def test_open_redirect_not_flagged_when_safe(make_server):
    def handler(h):
        h.send_response(200)
        h.end_headers()
        h.wfile.write(b"ok")

    base = make_server({"/": handler})
    client = WebvClient()
    assert check_open_redirect(client, base + "/") == []
