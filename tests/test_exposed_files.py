from webv.checks.exposed_files import check_exposed_files
from webv.http_client import WebvClient


def test_exposed_git_config_detected(make_server):
    def git_config(h):
        h.send_response(200)
        h.end_headers()
        h.wfile.write(b"[core]\n\trepositoryformatversion = 0\n")

    def root(h):
        h.send_response(200)
        h.end_headers()
        h.wfile.write(b"<html>home</html>")

    base = make_server({"/.git/config": git_config, "/": root})
    client = WebvClient()
    findings = check_exposed_files(client, base)
    types = [f["type"] for f in findings]
    assert "Exposed Sensitive File" in types


def test_nothing_exposed_when_everything_404s(make_server):
    def root(h):
        h.send_response(200)
        h.end_headers()
        h.wfile.write(b"<html>home</html>")

    base = make_server({"/": root})
    client = WebvClient()
    assert check_exposed_files(client, base) == []
