"""Static knowledge used to turn a bare finding into a lesson.

Each entry backs one "card" in the HTML report: what it is, why it matters,
how the check actually worked, which OWASP Top 10 (2021) category it maps to,
and a safe, legal target where a learner can go practice exploiting (and then
fixing) that exact class of bug.
"""

VULN_INFO = {
    "XSS": {
        "description": "Cross-Site Scripting — attacker-controlled script reflected in the page without sanitization.",
        "risk": "Session hijacking, credential theft, or malicious redirects affecting site users.",
        "fix": "HTML-encode all user-supplied input on output. Use a Content Security Policy header.",
        "how_detected": "A payload like <script>alert(1)</script> was sent as a parameter value, then the "
                         "response was checked to see if that exact string came back unescaped (not turned "
                         "into &lt;script&gt;). If it did, the browser would run it as real HTML/JS.",
        "owasp_category": "A03:2021 — Injection",
        "practice_target": "OWASP Juice Shop (score board XSS challenges) — https://owasp.org/www-project-juice-shop/",
    },
    "SQL Injection": {
        "description": "User input is concatenated into a SQL query without parameterization.",
        "risk": "Full database compromise, authentication bypass, and potential RCE via xp_cmdshell.",
        "fix": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "how_detected": "A payload such as ' or ' OR 1=1 -- was sent as a parameter value. The response was "
                         "then matched against known database error strings (error-based), compared against a "
                         "logically-true vs logically-false version of the same query (boolean-based), or timed "
                         "against a SLEEP()-style payload (time-based) to infer the query ran unsafely.",
        "owasp_category": "A03:2021 — Injection",
        "practice_target": "PortSwigger Web Security Academy — SQL injection labs (free) — https://portswigger.net/web-security/sql-injection",
    },
    "Missing Header": {
        "description": "One or more recommended HTTP security headers are absent from the response.",
        "risk": "Increased exposure to clickjacking, MIME sniffing, and cross-site scripting attacks.",
        "fix": "Add X-Frame-Options, Content-Security-Policy, and X-Content-Type-Options to all responses.",
        "how_detected": "The response headers were read directly and compared against a checklist of "
                         "commonly-recommended security headers.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "securityheaders.com — scan any site you own to see your own header grade.",
    },
    "Insecure Cookie": {
        "description": "A session or other cookie is missing a security flag (Secure, HttpOnly, or SameSite).",
        "risk": "Without HttpOnly, JavaScript (including injected XSS) can read the cookie. Without Secure, "
                "it can be sent over plain HTTP. Without SameSite, it can be sent on cross-site requests, "
                "enabling CSRF.",
        "fix": "Set Secure, HttpOnly, and SameSite=Lax/Strict on every session cookie.",
        "how_detected": "The Set-Cookie response header(s) were parsed and checked for the Secure, HttpOnly, "
                         "and SameSite attributes.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "PortSwigger Web Security Academy — session hijacking labs.",
    },
    "Clickjacking": {
        "description": "The page can be embedded in an <iframe> on another site with no framing protection.",
        "risk": "An attacker can overlay invisible buttons on top of your real UI and trick users into clicking "
                "them (e.g. 'confirm transfer') while believing they're on the attacker's page.",
        "fix": "Send X-Frame-Options: DENY/SAMEORIGIN, or a CSP frame-ancestors directive.",
        "how_detected": "Checked for the absence of both X-Frame-Options and a CSP frame-ancestors directive, "
                         "which together are the only things that stop framing.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "OWASP clickjacking cheat sheet + a self-hosted test page with an <iframe>.",
    },
    "Open Port": {
        "description": "A network port is open and a service is accepting connections.",
        "risk": "Exposed services expand the attack surface — especially if unpatched or misconfigured.",
        "fix": "Close unused ports via firewall rules. Keep all exposed services updated and hardened.",
        "how_detected": "Nmap performed a fast TCP scan of common ports against the target host.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "TryHackMe 'Nmap' room.",
    },
    "Nikto Finding": {
        "description": "Nikto identified a potential server misconfiguration or known vulnerability.",
        "risk": "Varies by finding — may indicate outdated software, dangerous HTTP methods, or info leakage.",
        "fix": "Review each Nikto finding individually and update or reconfigure the affected component.",
        "how_detected": "The external Nikto scanner was run against the host and its findings were parsed.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "n/a — Nikto findings vary per server.",
    },
    "CORS Misconfiguration": {
        "description": "Server allows cross-origin requests from untrusted or arbitrary origins.",
        "risk": "An attacker-controlled site can read authenticated API responses, leading to data theft.",
        "fix": "Set Access-Control-Allow-Origin to specific trusted domains. Never use wildcard with credentials.",
        "how_detected": "A request was sent with Origin: https://evil-attacker.com. The response's "
                         "Access-Control-Allow-Origin / -Allow-Credentials headers were checked for a wildcard "
                         "or a reflected-origin-plus-credentials combination.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "PortSwigger Web Security Academy — CORS labs.",
    },
    "Open Redirect": {
        "description": "Application redirects users to externally supplied URLs without validation.",
        "risk": "Used in phishing attacks — attacker crafts a trusted-looking link redirecting to a malicious site.",
        "fix": "Validate redirect targets server-side. Use a whitelist of allowed destination URLs.",
        "how_detected": "Common redirect parameter names (redirect, url, next, ...) were set to an external URL "
                         "and the Location header of the (non-followed) response was checked.",
        "owasp_category": "A01:2021 — Broken Access Control",
        "practice_target": "PortSwigger Web Security Academy — open redirection labs.",
    },
    "Potential SSRF": {
        "description": "A parameter accepts a URL-shaped value and may cause the server to fetch it.",
        "risk": "If the server fetches attacker-supplied URLs, it can be tricked into reaching internal-only "
                "services (e.g. cloud metadata endpoints) that are otherwise unreachable from outside.",
        "fix": "Validate and allow-list destination hosts server-side; never let user input choose the fetch target.",
        "how_detected": "This is a heuristic, not a confirmed exploit: the parameter's name/value shape looked "
                         "URL-like (e.g. url=, webhook=, callback=). Manual confirmation with a controlled "
                         "listener is needed before treating this as a real finding.",
        "owasp_category": "A10:2021 — Server-Side Request Forgery",
        "practice_target": "PortSwigger Web Security Academy — SSRF labs.",
    },
    "Potential IDOR": {
        "description": "Changing an object's ID in an authenticated request returned another user's data.",
        "risk": "Any authenticated user can read or modify other users' records by guessing/incrementing an ID.",
        "fix": "Check the authenticated user actually owns/can access the requested object server-side, every time.",
        "how_detected": "With an authenticated session, a numeric ID found in a URL/param was swapped for an "
                         "adjacent value and the two authenticated responses were diffed for an unexpected "
                         "200-with-different-content.",
        "owasp_category": "A01:2021 — Broken Access Control",
        "practice_target": "PortSwigger Web Security Academy — access control labs.",
    },
    "Exposed Sensitive File": {
        "description": "A file that should never be publicly served (source control data, env vars, backups) is reachable.",
        "risk": "These files routinely contain credentials, API keys, or source code that materially helps an attacker.",
        "fix": "Remove the file from the web root, or block it at the web server/reverse proxy level.",
        "how_detected": "A direct GET request was sent to a list of well-known sensitive paths (.git/config, "
                         ".env, backups, etc.) and the response was checked for a 200 status with recognizable content.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "git-dumper challenges on TryHackMe/HackTheBox.",
    },
    "Directory Listing": {
        "description": "The web server returns a browsable file index for a directory instead of a page or a 403/404.",
        "risk": "Reveals file/directory names an attacker wouldn't otherwise know about, aiding further recon.",
        "fix": "Disable directory indexing/autoindex in your web server configuration.",
        "how_detected": "The response body matched the standard 'Index of /...' directory-listing pattern.",
        "owasp_category": "A05:2021 — Security Misconfiguration",
        "practice_target": "n/a — configuration issue, easy to reproduce locally with any dev web server.",
    },
    "No HTTPS": {
        "description": "Site uses plain HTTP with no TLS encryption.",
        "risk": "All traffic including credentials and session tokens is transmitted in plaintext.",
        "fix": "Obtain a TLS certificate (e.g. via Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
        "how_detected": "The target URL's scheme was checked directly.",
        "owasp_category": "A02:2021 — Cryptographic Failures",
        "practice_target": "n/a — set up Let's Encrypt on a test VM to see the fix.",
    },
    "SSL Certificate Expiring": {
        "description": "The TLS certificate is close to its expiry date.",
        "risk": "Browsers will display security warnings and connections may be refused after expiry.",
        "fix": "Renew the certificate before it expires. Consider automated renewal with certbot.",
        "how_detected": "A raw TLS handshake was performed and the certificate's notAfter date was compared to now.",
        "owasp_category": "A02:2021 — Cryptographic Failures",
        "practice_target": "n/a — operational hygiene issue.",
    },
    "Invalid SSL Certificate": {
        "description": "The TLS certificate cannot be verified against a trusted Certificate Authority.",
        "risk": "Enables man-in-the-middle attacks — attackers can intercept and read all traffic.",
        "fix": "Replace self-signed certificates with ones issued by a trusted CA.",
        "how_detected": "A raw TLS handshake using the system's default trust store failed verification.",
        "owasp_category": "A02:2021 — Cryptographic Failures",
        "practice_target": "n/a — operational hygiene issue.",
    },
    "Weak TLS Cipher": {
        "description": "The server negotiated a cipher suite with known cryptographic weaknesses.",
        "risk": "Encrypted traffic may be decryptable by an attacker with sufficient resources.",
        "fix": "Disable RC4, DES, 3DES, EXPORT, and NULL cipher suites in your server TLS configuration.",
        "how_detected": "The negotiated cipher name from the TLS handshake was checked against a known-weak list.",
        "owasp_category": "A02:2021 — Cryptographic Failures",
        "practice_target": "n/a — operational hygiene issue.",
    },
}


def get_info(vuln_type: str) -> dict:
    return VULN_INFO.get(vuln_type, {
        "description": "N/A",
        "risk": "N/A",
        "fix": "N/A",
        "how_detected": "N/A",
        "owasp_category": "N/A",
        "practice_target": "N/A",
    })
