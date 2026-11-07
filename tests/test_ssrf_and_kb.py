from webv.checks.ssrf import check_ssrf_point
from webv.knowledge_base import get_info
from webv.params import InjectionPoint


def test_ssrf_flags_suspicious_param_name():
    point = InjectionPoint(url="http://x/fetch", method="get", param="url", location="query")
    findings = check_ssrf_point(point)
    assert len(findings) == 1
    assert findings[0]["confidence"] == "Low"


def test_ssrf_ignores_ordinary_param_name():
    point = InjectionPoint(url="http://x/search", method="get", param="term", location="query")
    assert check_ssrf_point(point) == []


def test_knowledge_base_has_entry_for_every_check_type():
    for vtype in ["XSS", "SQL Injection", "Missing Header", "Insecure Cookie", "Clickjacking",
                  "CORS Misconfiguration", "Open Redirect", "Potential SSRF", "Potential IDOR",
                  "Exposed Sensitive File", "Directory Listing"]:
        info = get_info(vtype)
        assert info["description"] != "N/A"
        assert info["how_detected"] != "N/A"


def test_knowledge_base_unknown_type_is_safe():
    info = get_info("Something Made Up")
    assert info["description"] == "N/A"
