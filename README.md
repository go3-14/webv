# Web Vulnerability Scanner (webv)

A command-line vulnerability scanner built to **learn appsec by using it**,
not to compete with Burp/ZAP/Nessus. Every finding explains what it is, why
it matters, exactly how webv detected it, and where you can go practice that
exact bug legally.

---

## Features

* CLI commands: `scan`, `add`, `list`, `learn`, `quickstart`, `login-test`
* Three scan modes:
  * `--fast` — baseline checks only, no crawl, no external tools (seconds)
  * (default) `normal` — adds Nikto (if installed)
  * `--deep` — crawls the site, discovers every `<form>` field and query
    param, fuzzes all of them, adds Nikto + Nmap (if installed)
* **Dynamic injection point discovery** — crawls same-origin pages/forms
  instead of only testing a hardcoded `?q=`/`?id=`
* **Context-aware XSS** — classifies where a payload reflects (HTML body /
  tag attribute / `<script>` block) before deciding what "exploitable" means
* **Three SQLi techniques** — error-based (DB error signatures), boolean-based
  blind, and time-based blind (deep mode)
* **Basic authenticated scanning** — static cookie/header, or a form-login
  flow, applied to the whole scan via `--auth auth.json`
* Checks: missing security headers, insecure cookies, clickjacking, CORS
  misconfiguration, open redirect, SSL/TLS issues, exposed sensitive files
  (`.git`, `.env`, backups), directory listing, a conservative IDOR heuristic
  (auth-gated, opt-in), and a passive SSRF-parameter flagger
* Custom payload support (XSS, SQLi) via `payloads.json`
* Every finding in the HTML report includes: description, risk, fix, **how
  webv detected it**, its OWASP Top 10 (2021) category, a link to a legal
  practice target, and (where applicable) the raw request/response

---

## Installation

```bash
git clone https://github.com/go3-14/webv.git
cd webv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional external tools (used in normal/deep modes, gracefully skipped if
missing):

```bash
sudo apt update
sudo apt install nmap nikto
```

Optional, for crawling JS-rendered pages in `--deep` mode:

```bash
pip install playwright && playwright install chromium
```

---

## Usage

New to this? Start here:

```bash
python main.py quickstart
```

### Scan

```bash
python main.py scan <url>              # normal mode
python main.py scan <url> --fast       # quick, no crawl/external tools
python main.py scan <url> --deep       # crawl + fuzz every discovered param
```

You'll be asked to confirm you're authorized to scan the target. Skip the
prompt in scripts with `--i-have-permission`.

### Authenticated scanning

Create an `auth.json`:

```json
{
  "login_url": "http://localhost:3000/rest/user/login",
  "username_field": "email",
  "password_field": "password",
  "username": "test@example.com",
  "password": "test1234",
  "success_indicator": "authentication"
}
```

(or, for a static credential: `{"cookie": "session=abc123"}`)

```bash
python main.py login-test --auth auth.json <url>   # verify it works first
python main.py scan <url> --auth auth.json --deep --enable-idor
```

### Learn / payloads

```bash
python main.py learn xss          # short lesson on a vuln class
python main.py add --type xss --payload "<svg onload=alert(1)>"
python main.py list
```

---

## Output

Generates `report_<timestamp>.html` with:

* Overall risk + High/Medium/Low counts
* Discovered endpoints (normal/deep mode)
* Every finding, enriched with a "how this was detected" explanation, its
  OWASP category, a legal practice-target link, and an expandable raw
  request/response transcript

---

## Project Structure

```plaintext
main.py                    # thin entry point
webv/
  cli.py                    # argparse entry
  config.py                 # ScanConfig / AuthConfig
  http_client.py            # shared session, auth, rate limiting
  auth.py                    # auth.json loading + login-test
  crawler.py                 # same-origin BFS crawl, <form> parsing
  params.py                  # injection point discovery from crawled pages
  scanner.py                  # orchestrates checks -> report
  report.py                   # Jinja2 HTML report (autoescaped)
  learn.py                    # `learn` / `quickstart` commands
  payloads.py                 # payloads.json load/save
  knowledge_base.py           # description/risk/fix/how-detected/OWASP tag/practice target
  checks/                      # one module per vulnerability class
  external/                    # nikto.py / nmap.py / dependency checks
tests/                        # pytest unit tests, local HTTP fixtures only
payloads.json
requirements.txt
```

---

## Notes

* Fast mode skips crawling and external tools for speed.
* Deep mode crawls, fuzzes every discovered form field/query param, and runs
  Nikto/Nmap if installed.
* The IDOR check only runs with `--enable-idor` **and** a working
  authenticated session — it reports findings at Low confidence and always
  needs manual confirmation.
* The SSRF check is a passive heuristic (parameter name/shape only) — it
  never attempts to actually reach internal/metadata endpoints.

---

## Disclaimer

This tool is intended for educational purposes only.
Do not scan systems without proper authorization.

---

## Author

Gopi K
