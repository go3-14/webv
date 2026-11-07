"""HTML report generation, now via Jinja2 (autoescape=True) instead of raw
f-strings. Autoescaping is load-bearing here: several findings embed
attacker-controlled strings (XSS/SQLi payloads, exposed file paths) that must
never render as live HTML in the report itself.
"""

from datetime import datetime

from jinja2 import Environment

from .knowledge_base import get_info

_ENV = Environment(autoescape=True)

_TEMPLATE = _ENV.from_string("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebV Report — {{ url }}</title>
<style>
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }
.header { background: #1e293b; padding: 20px; text-align: center; border-bottom: 2px solid #334155; }
.container { padding: 20px; max-width: 980px; margin: 0 auto; }
.card { background: #1e293b; padding: 15px; margin: 15px 0; border-radius: 10px;
        box-shadow: 0 4px 10px rgba(0,0,0,0.3); border-left: 4px solid #475569; }
.card.high   { border-left-color: #ef4444; }
.card.medium { border-left-color: #f59e0b; }
.card.low    { border-left-color: #22c55e; }
.badge { padding: 3px 10px; border-radius: 5px; font-weight: bold; font-size: 0.85em; }
.high   { background: #ef4444; }
.medium { background: #f59e0b; color: #000; }
.low    { background: #22c55e; color: #000; }
.summary { display: flex; gap: 20px; margin-bottom: 20px; }
.box { flex: 1; padding: 20px; border-radius: 10px; text-align: center; font-size: 1.4em; font-weight: bold; }
.box.high   { background: #7f1d1d; }
.box.medium { background: #78350f; }
.box.low    { background: #14532d; }
ul { line-height: 1.8; }
code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; word-break: break-all; }
.tag { display: inline-block; background: #334155; color: #cbd5e1; padding: 2px 8px; border-radius: 12px;
       font-size: 0.78em; margin-left: 6px; }
.legend { font-size: 0.85em; color: #94a3b8; margin-top: 10px; }
.learn { background: #0f172a; border-radius: 8px; padding: 10px 14px; margin-top: 10px; }
.learn a { color: #60a5fa; }
details { margin-top: 10px; }
summary { cursor: pointer; color: #94a3b8; }
pre { background: #0f172a; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 0.82em; }
</style>
</head>
<body>
<div class="header">
    <h1>&#128269; Web Vulnerability Report</h1>
    <p><b>Target:</b> <code>{{ url }}</code></p>
    <p><b>Scan Mode:</b> {{ mode }}</p>
    <p><b>Generated:</b> {{ generated_at }}</p>
    <h2>Overall Risk: <span class="badge {{ risk|lower }}">{{ risk }}</span></h2>
    <p class="legend">
        Severity = how bad it is if exploited. Confidence = how sure webv is this isn't a false positive
        (High = directly confirmed, Medium = strong signal but worth double-checking, Low = heuristic,
        needs manual confirmation before acting on it).
    </p>
</div>
<div class="container">
<h2>Summary</h2>
<div class="summary">
    <div class="box high">High<br>{{ high_count }}</div>
    <div class="box medium">Medium<br>{{ medium_count }}</div>
    <div class="box low">Low<br>{{ low_count }}</div>
</div>

{% if endpoints %}
<h2>Discovered Endpoints</h2>
<div class="card">
<ul>
{% for ep in endpoints %}
    <li><code>{{ ep }}</code></li>
{% endfor %}
</ul>
</div>
{% endif %}

<h2>Findings</h2>
{% if not vulns %}
<div class="card"><p>&#10003; No vulnerabilities detected.</p></div>
{% else %}
{% for v in vulns %}
<div class="card {{ v.severity|lower }}">
    <h3>{{ v.type }}
        <span class="badge {{ v.severity|lower }}">{{ v.severity }}</span>
        <span class="tag">{{ v.info.owasp_category }}</span>
    </h3>
    <p><b>Details:</b> {{ v.detail }}</p>
    <p><b>Description:</b> {{ v.info.description }}</p>
    <p><b>Risk:</b> {{ v.info.risk }}</p>
    <p><b>Fix:</b> {{ v.info.fix }}</p>
    <p><b>Confidence:</b> {{ v.confidence }}</p>
    <div class="learn">
        <p><b>How this was detected:</b> {{ v.info.how_detected }}</p>
        <p><b>Try it yourself (legally):</b> {{ v.info.practice_target }}</p>
    </div>
    {% if v.transcript %}
    <details>
        <summary>Raw request/response</summary>
        <pre>{{ v.transcript.method }} {{ v.transcript.url }}
HTTP {{ v.transcript.status_code }}

{{ v.transcript.response_snippet }}</pre>
    </details>
    {% endif %}
</div>
{% endfor %}
{% endif %}
</div>
</body>
</html>
""")


def overall_risk(vulns: list) -> str:
    if any(v["severity"] == "High" for v in vulns):
        return "High"
    if any(v["severity"] == "Medium" for v in vulns):
        return "Medium"
    return "Low"


def generate_report(vulns: list, url: str, mode: str, endpoints: list) -> str:
    high = sum(1 for v in vulns if v["severity"] == "High")
    medium = sum(1 for v in vulns if v["severity"] == "Medium")
    low = sum(1 for v in vulns if v["severity"] == "Low")

    enriched = []
    for v in vulns:
        enriched.append({**v, "info": get_info(v["type"])})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.html"

    html = _TEMPLATE.render(
        url=url,
        mode=mode,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        risk=overall_risk(vulns),
        high_count=high,
        medium_count=medium,
        low_count=low,
        endpoints=endpoints,
        vulns=enriched,
    )

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename
