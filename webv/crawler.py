"""Same-origin BFS crawler: discovers pages, <a> links, and <form> fields.

Kept deliberately simple (no JS execution) by default. When Playwright is
installed and --deep is used, a rendered pass can be layered on top later —
see config.ScanConfig.use_playwright — but the pure-HTML crawl below is
always the baseline so the tool has zero hard dependency on a browser.
"""

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup

from .http_client import WebvClient


@dataclass
class Page:
    url: str
    status_code: int
    html: str
    forms: list = field(default_factory=list)  # list of dicts: method, action, fields


@dataclass
class Form:
    action: str
    method: str
    fields: List[str]


# Best-effort: pick up obvious fetch('/api/...')-style calls in inline <script>
# blocks so simple JSON APIs get discovered without running a real JS engine.
_JS_FETCH_RE = re.compile(r"""(?:fetch|axios\.(?:get|post))\(\s*['"]([^'"]+)['"]""")


def _same_origin(base: str, candidate: str) -> bool:
    return urlparse(base).netloc == urlparse(candidate).netloc


def _parse_forms(soup: BeautifulSoup, page_url: str) -> list:
    forms = []
    for tag in soup.find_all("form"):
        action = urljoin(page_url, tag.get("action") or page_url)
        method = (tag.get("method") or "get").lower()
        fields = []
        for inp in tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                fields.append(name)
        if fields:
            forms.append(Form(action=action, method=method, fields=fields))
    return forms


def crawl(client: WebvClient, start_url: str, max_depth: int = 2, max_pages: int = 25) -> List[Page]:
    """Breadth-first, same-origin crawl. Returns every page fetched (including
    the start page), each with its discovered forms attached."""
    seen = {start_url}
    queue = deque([(start_url, 0)])
    pages: List[Page] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        res, _ = client.get(url)
        if res is None:
            continue

        html = res.text if "html" in res.headers.get("content-type", "") else ""
        soup = BeautifulSoup(html, "html.parser") if html else None
        forms = _parse_forms(soup, url) if soup else []
        pages.append(Page(url=url, status_code=res.status_code, html=html, forms=forms))

        if depth >= max_depth:
            continue

        if soup:
            for tag in soup.find_all("a"):
                href = tag.get("href")
                if not href or href.startswith("#") or href.startswith("mailto:"):
                    continue
                full = urljoin(url, href)
                if _same_origin(start_url, full) and full not in seen:
                    seen.add(full)
                    queue.append((full, depth + 1))

            for script in soup.find_all("script"):
                for match in _JS_FETCH_RE.findall(script.get_text() or ""):
                    full = urljoin(url, match)
                    if _same_origin(start_url, full) and full not in seen:
                        seen.add(full)
                        queue.append((full, depth + 1))

    logging.info("Crawl discovered %d page(s).", len(pages))
    return pages
