# webv — Web Vulnerability Scanner

A command-line vulnerability scanner built to **learn appsec by using it**.
It isn't trying to compete with Burp Suite, ZAP, or Nessus — every finding
it produces explains what the bug is, why it matters, exactly how webv
detected it, and where you can go practice that exact class of bug legally.

## Table of Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Scanning](#scanning)
  - [Authenticated scanning](#authenticated-scanning)
  - [Learning / payloads](#learning--payloads)
- [Output](#output)
- [Project structure](#project-structure)
- [Notes](#notes)
- [Disclaimer](#disclaimer)
- [Author](#author)

## Quick start

```bash
git clone https://github.com/go3-14/webv.git
cd webv
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python main.py quickstart          # guided first-scan walkthrough
python main.py scan <url> --fast   # a result in seconds
```

## Features

**Detection**
- Dynamic injection-point discovery — crawls the site and parses every
  `<form>` field and query param, instead of only testing a hardcoded
  `?q=`/`?id=`
- Context-aware XSS — classifies *where* a payload reflects (HTML body /
  tag attribute / `<script>` block) and shapes the payload accordingly
- SQL injection via three techniques: error-based, boolean-based blind, and
  time-based blind (deep mode)
- Missing security headers, insecure cookies, clickjacking, CORS
  misconfiguration, open redirect, SSL/TLS issues
- Exposed sensitive files (`.git`, `.env`, backups) and directory listing
- A conservative, auth-gated IDOR heuristic and a passive SSRF
  parameter flagger
- Custom payload support (XSS, SQLi) via `payloads.json`

**Learning**
- Every report finding explains **how it was detected**, tags its OWASP
  Top 10 (2021) category, and links a legal practice target for that bug
- `webv learn <topic>` — a short lesson on any vuln class, no scan required
- `webv quickstart` — a guided first-scan walkthrough
- An authorization confirmation prompt before every scan

**Scanning modes**
| Mode | What it does |
|------|---------------|
| `--fast` | Baseline checks only — no crawl, no external tools. Seconds. |
| *(default)* | Adds Nikto, if installed. |
| `--deep` | Crawls the site, fuzzes every discovered form field/query param, adds Nikto + Nmap if installed. |

**Auth**
- Static cookie/header, or a form-login flow — applied once and reused
  across the whole scan via `--auth auth.json`

## Installation

```bash
git clone https://github.com/go3-14/webv.git
cd webv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional external tools (used in normal/deep modes, skipped gracefully if
missing):

```bash
sudo apt update
sudo apt install nmap nikto
```

Optional, for crawling JS-rendered pages in `--deep` mode:

```bash
pip install playwright && playwright install chromium
```

## Usage

New to this? Start here:

```bash
python main.py quickstart
```

### Scanning

```bash
python main.py scan <url>              # normal mode
python main.py scan <url> --fast       # quick, no crawl/external tools
python main.py scan <url> --deep       # crawl + fuzz every discovered param
```

You'll be asked to confirm you're authorized to scan the target. Skip the
prompt in scripts with `--i-have-permission`.

Other scan flags: `--verbose` (debug logging), `--explain` (narrate each
check as it runs), `--concurrency N` and `--delay N` (throttle fuzzing),
`--max-depth N` / `--max-pages N` (crawl limits), `--enable-idor` (opt in to
the auth-gated IDOR heuristic).

### Authenticated scanning

Create an `auth.json` (see [`auth.json.example`](auth.json.example)):

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

Or for a static credential: `{"cookie": "session=abc123"}`

```bash
python main.py login-test --auth auth.json <url>   # verify it works first
python main.py scan <url> --auth auth.json --deep --enable-idor
```

### Learning / payloads

```bash
python main.py learn xss          # short lesson on a vuln class
python main.py add --type xss --payload "<svg onload=alert(1)>"
python main.py list
```

## Output

Generates `report_<timestamp>.html` containing:

- Overall risk + High/Medium/Low counts
- Discovered endpoints (normal/deep mode)
- Every finding, enriched with a "how this was detected" explanation, its
  OWASP category, a legal practice-target link, and an expandable raw
  request/response transcript

## Project structure

```text
main.py                     # thin entry point
webv/
  cli.py                     # argparse entry
  config.py                  # ScanConfig / AuthConfig
  http_client.py             # shared session, auth, rate limiting
  auth.py                    # auth.json loading + login-test
  crawler.py                 # same-origin BFS crawl, <form> parsing
  params.py                  # injection point discovery from crawled pages
  scanner.py                 # orchestrates checks -> report
  report.py                  # Jinja2 HTML report (autoescaped)
  learn.py                   # `learn` / `quickstart` commands
  payloads.py                # payloads.json load/save
  knowledge_base.py          # description/risk/fix/how-detected/OWASP tag/practice target
  checks/                    # one module per vulnerability class
  external/                  # nikto.py / nmap.py / dependency checks
tests/                       # pytest unit tests, local HTTP fixtures only
payloads.json
requirements.txt
```

## Notes

- Fast mode skips crawling and external tools for speed.
- Deep mode crawls, fuzzes every discovered form field/query param, and
  runs Nikto/Nmap if installed.
- The IDOR check only runs with `--enable-idor` **and** a working
  authenticated session — findings are reported at Low confidence and
  always need manual confirmation.
- The SSRF check is a passive heuristic (parameter name/shape only) — it
  never attempts to actually reach internal/metadata endpoints.

## Disclaimer

This tool is intended for educational purposes only.
Do not scan systems without proper authorization.

## Author

Gopi K
