from webv.crawler import Form, Page
from webv.params import InjectionPoint, discover_injection_points


def test_discovers_query_params():
    pages = [Page(url="http://x/?a=1&b=2", status_code=200, html="", forms=[])]
    points = discover_injection_points(pages)
    params = {p.param for p in points}
    assert params == {"a", "b"}
    assert all(p.location == "query" for p in points)


def test_discovers_form_fields_and_keeps_other_fields():
    form = Form(action="http://x/login", method="post", fields=["username", "password"])
    pages = [Page(url="http://x/", status_code=200, html="", forms=[form])]
    points = discover_injection_points(pages)
    by_param = {p.param: p for p in points}
    assert set(by_param) == {"username", "password"}
    assert by_param["username"].other_fields == ("password",)
    assert by_param["password"].other_fields == ("username",)


def test_deduplicates_identical_point_seen_twice():
    pages = [
        Page(url="http://x/?a=1", status_code=200, html="", forms=[]),
        Page(url="http://x/?a=1", status_code=200, html="", forms=[]),
    ]
    points = discover_injection_points(pages)
    assert len(points) == 1
