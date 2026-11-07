"""Turn crawled pages into a flat list of concrete injection points to fuzz.

v1 only ever tested ?q= and ?id= on the start URL. This collects every query
string param already on a URL, every <form> field discovered by the crawler,
and de-duplicates so the same (url, param) pair isn't tested twice.
"""

from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse, parse_qs

from .crawler import Page


@dataclass(frozen=True)
class InjectionPoint:
    url: str          # for query params: the page URL; for forms: the action URL
    method: str        # "get" or "post"
    param: str
    location: str       # "query" | "form"
    other_fields: tuple = ()  # other field names on the same form, kept as-is when fuzzing `param`


def discover_injection_points(pages: List[Page]) -> List[InjectionPoint]:
    points = []
    seen = set()

    def add(point: InjectionPoint):
        key = (point.url, point.method, point.param, point.location)
        if key not in seen:
            seen.add(key)
            points.append(point)

    for page in pages:
        query = parse_qs(urlparse(page.url).query)
        for param in query:
            add(InjectionPoint(url=page.url, method="get", param=param, location="query"))

        for form in page.forms:
            for field in form.fields:
                others = tuple(f for f in form.fields if f != field)
                add(InjectionPoint(
                    url=form.action, method=form.method, param=field,
                    location="form", other_fields=others,
                ))

    return points
