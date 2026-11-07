import os

from webv.report import generate_report


def test_report_escapes_attacker_controlled_detail(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    vulns = [{
        "type": "XSS",
        "detail": "Unescaped payload reflected: <script>alert(1)</script>",
        "severity": "High",
        "confidence": "High",
    }]
    path = generate_report(vulns, "http://example.com", "FAST", [])
    content = (tmp_path / path).read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


def test_report_no_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = generate_report([], "http://example.com", "FAST", [])
    content = (tmp_path / path).read_text(encoding="utf-8")
    assert "No vulnerabilities detected" in content
