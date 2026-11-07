"""`webv learn <topic>` and `webv quickstart` — the teaching surface of the tool.

These exist because the HTML report is only useful after you've already run
a scan. New users need somewhere to start before that.
"""

from .knowledge_base import VULN_INFO

_TOPIC_ALIASES = {
    "xss": "XSS",
    "sqli": "SQL Injection",
    "sql": "SQL Injection",
    "cors": "CORS Misconfiguration",
    "redirect": "Open Redirect",
    "ssrf": "Potential SSRF",
    "idor": "Potential IDOR",
    "clickjacking": "Clickjacking",
    "cookies": "Insecure Cookie",
    "headers": "Missing Header",
    "exposed-files": "Exposed Sensitive File",
}

QUICKSTART = """
webv quickstart
================

1. Pick a target you're actually allowed to scan. Three good, free, legal
   options to practice on:
     - OWASP Juice Shop (run locally): https://owasp.org/www-project-juice-shop/
     - testphp.vulnweb.com — a permanently-online intentionally vulnerable site
     - PortSwigger Web Security Academy labs (free account): https://portswigger.net/web-security

2. Run a fast scan first — no crawling, no external tools, just the quick
   checks, so you see output in seconds:

       python main.py scan http://testphp.vulnweb.com --fast

3. Open the generated report_<timestamp>.html in a browser. For every
   finding, read the "How this was detected" and "Try it yourself" sections
   before the fix — understanding the attack is what makes the fix make sense.

4. Once that makes sense, run a normal scan (adds Nikto if installed) and
   then a deep scan (crawls the site, tests every discovered form/param, and
   adds Nmap if installed):

       python main.py scan http://testphp.vulnweb.com
       python main.py scan http://testphp.vulnweb.com --deep

5. Try `python main.py learn xss` (or sqli / cors / idor / ...) any time you
   want the short version of a vuln class without running a scan.

6. When you're ready to test pages that need a login, look at the auth.json
   example in README.md and run:

       python main.py login-test --auth auth.json <url>

   before pointing a real scan at an authenticated app.

Always get explicit permission before scanning anything you don't own.
"""


def print_quickstart():
    print(QUICKSTART)


def print_topic(topic: str):
    key = _TOPIC_ALIASES.get(topic.lower(), topic)
    info = VULN_INFO.get(key)
    if not info:
        known = ", ".join(sorted(_TOPIC_ALIASES.keys()))
        print(f"Unknown topic '{topic}'. Try one of: {known}")
        return

    print(f"\n{key}  [{info['owasp_category']}]")
    print("-" * (len(key) + len(info["owasp_category"]) + 3))
    print(f"What it is:    {info['description']}")
    print(f"Why it matters: {info['risk']}")
    print(f"How webv finds it: {info['how_detected']}")
    print(f"How to fix it: {info['fix']}")
    print(f"Practice here: {info['practice_target']}\n")
