"""Orchestrates a scan: wires the crawler, injection-point discovery, every
check module, and the optional external tools together, then hands the
results to report.py.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from .checks.clickjacking import check_clickjacking
from .checks.cookies import check_cookies
from .checks.cors import check_cors
from .checks.exposed_files import check_exposed_files
from .checks.headers import check_headers
from .checks.idor import check_idor_value
from .checks.redirect import check_open_redirect
from .checks.sqli import check_sql_point
from .checks.ssl_tls import check_ssl
from .checks.ssrf import check_ssrf_point
from .checks.xss import check_xss_point
from .config import ScanConfig
from .crawler import crawl
from .external.dependencies import check_external_tools
from .external.nikto import parse_nikto, run_nikto
from .external.nmap import parse_nmap, run_nmap
from .http_client import WebvClient
from .params import discover_injection_points
from .payloads import load_payloads
from .report import generate_report


def _extract_host(url: str) -> str:
    return urlparse(url).netloc


def run_scan(config: ScanConfig) -> str | None:
    logging.info("Starting scan: %s (mode=%s)", config.url, config.mode)

    client = WebvClient(auth=config.auth, delay=config.delay)
    try:
        res, _ = client.get(config.url)
        if res is None:
            logging.error("Could not reach target URL. Aborting.")
            return None

        if config.auth and not client.authenticated:
            logging.warning("Auth was configured but did not succeed — scanning unauthenticated.")

        vulns = []
        payloads = load_payloads()

        if config.check_enabled("headers"):
            vulns.extend(check_headers(res))
        if config.check_enabled("cookies"):
            vulns.extend(check_cookies(res))
        if config.check_enabled("clickjacking"):
            vulns.extend(check_clickjacking(res))
        if config.check_enabled("ssl"):
            logging.info("Checking SSL/TLS configuration...")
            vulns.extend(check_ssl(config.url))
        if config.check_enabled("cors"):
            logging.info("Checking CORS configuration...")
            vulns.extend(check_cors(client, config.url))
        if config.check_enabled("redirect"):
            logging.info("Checking for open redirect...")
            vulns.extend(check_open_redirect(client, config.url))
        if config.check_enabled("exposed_files"):
            logging.info("Checking for exposed sensitive files...")
            vulns.extend(check_exposed_files(client, config.url))

        discovered_endpoints = []

        if config.is_fast:
            logging.info("Fast mode — baseline XSS/SQLi on the target URL only, no crawl, no external tools.")
            vulns.extend(check_xss_point(client, _base_point(config.url, "q"), payloads["xss"]))
            vulns.extend(check_sql_point(client, _base_point(config.url, "id"), payloads["sqli"]))
        else:
            max_depth = config.max_depth if config.is_deep else 1
            logging.info("Crawling to discover pages and forms...")
            pages = crawl(client, config.url, max_depth=max_depth, max_pages=config.max_pages)
            discovered_endpoints = [p.url for p in pages if p.url != config.url]

            points = discover_injection_points(pages)
            if not points:
                # Nothing discovered dynamically — fall back to the classic baseline.
                points = [_base_point(config.url, "q"), _base_point(config.url, "id")]
            logging.info("Found %d injection point(s) across %d page(s). Fuzzing...", len(points), len(pages))

            vulns.extend(_fuzz_points(client, points, payloads, config))

            if config.enable_idor and client.authenticated:
                vulns.extend(_run_idor(client, points))

            external = check_external_tools()
            if external["nikto"]:
                logging.info("Running Nikto...")
                vulns.extend(parse_nikto(run_nikto(config.url)))
            if config.is_deep and external["nmap"]:
                logging.info("Running Nmap...")
                vulns.extend(parse_nmap(run_nmap(_extract_host(config.url))))

        mode_label = config.mode.upper()
        report_path = generate_report(vulns, config.url, mode_label, discovered_endpoints)
        logging.info("Scan complete. %d finding(s) found.", len(vulns))
        logging.info("Report saved: %s", report_path)
        return report_path
    finally:
        client.close()


def _base_point(url: str, param: str):
    from .params import InjectionPoint
    return InjectionPoint(url=url, method="get", param=param, location="query")


def _fuzz_points(client: WebvClient, points: list, payloads: dict, config: ScanConfig) -> list:
    findings = []

    def work(point):
        results = []
        if config.check_enabled("xss"):
            results.extend(check_xss_point(client, point, payloads["xss"]))
        if config.check_enabled("sqli"):
            results.extend(check_sql_point(client, point, payloads["sqli"], deep=config.is_deep))
        if config.check_enabled("ssrf"):
            results.extend(check_ssrf_point(point))
        return results

    with ThreadPoolExecutor(max_workers=max(1, config.concurrency)) as pool:
        futures = {pool.submit(work, p): p for p in points}
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception as e:  # a single bad point shouldn't kill the scan
                logging.debug("Fuzzing %s failed: %s", futures[future], e)

    return findings


def _run_idor(client: WebvClient, points: list) -> list:
    findings = []
    for point in points:
        other = {f: "1" for f in point.other_fields}
        try:
            from urllib.parse import parse_qs, urlparse
            current_value = None
            if point.location == "query":
                qs = parse_qs(urlparse(point.url).query)
                current_value = (qs.get(point.param) or [None])[0]
            if current_value and current_value.isdigit():
                findings.extend(check_idor_value(
                    client, point.url, point.method, point.param, current_value, other
                ))
        except Exception as e:
            logging.debug("IDOR probe failed for %s: %s", point, e)
    return findings
