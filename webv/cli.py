"""webv CLI entry point."""

import argparse
import logging
import sys

from . import __version__
from .auth import load_auth, login_test
from .config import ScanConfig
from .learn import print_quickstart, print_topic
from .payloads import add_payload, list_payloads
from .scanner import run_scan


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")


def print_banner() -> None:
    banner = r"""
██╗    ██╗███████╗██████╗ ██╗   ██╗
██║    ██║██╔════╝██╔══██╗██║   ██║
██║ █╗ ██║█████╗  ██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝

   Web Vulnerability Scanner (webv) v{version}
"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(banner.format(version=__version__))


def _confirm_authorization(skip_prompt: bool) -> bool:
    if skip_prompt:
        return True
    print(
        "webv is for scanning systems you own or are explicitly authorized to test.\n"
        "Scanning a system without authorization may be illegal in your jurisdiction."
    )
    answer = input("Do you have authorization to scan this target? [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="webv — Web Vulnerability Scanner",
        epilog="Example: python main.py scan https://example.com --deep --verbose",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a target URL")
    scan_p.add_argument("target")
    scan_p.add_argument("--fast", action="store_true", help="Fast mode: baseline checks only, no crawl/external tools")
    scan_p.add_argument("--deep", action="store_true", help="Deep mode: crawl + fuzz every discovered param + Nikto + Nmap")
    scan_p.add_argument("--verbose", action="store_true")
    scan_p.add_argument("--explain", action="store_true", help="Print a short explanation before each check runs")
    scan_p.add_argument("--auth", help="Path to an auth.json for authenticated scanning")
    scan_p.add_argument("--enable-idor", action="store_true", help="Also run the (conservative, auth-required) IDOR heuristic")
    scan_p.add_argument("--concurrency", type=int, default=5)
    scan_p.add_argument("--delay", type=float, default=0.0, help="Seconds to wait between requests (politeness)")
    scan_p.add_argument("--max-depth", type=int, default=2)
    scan_p.add_argument("--max-pages", type=int, default=25)
    scan_p.add_argument("--i-have-permission", action="store_true", help="Skip the interactive authorization prompt")

    add_p = sub.add_parser("add", help="Add a custom payload")
    add_p.add_argument("--type", required=True, help="xss or sqli")
    add_p.add_argument("--payload", required=True)

    sub.add_parser("list", help="List stored payloads")

    learn_p = sub.add_parser("learn", help="Print a short lesson about a vuln class")
    learn_p.add_argument("topic")

    sub.add_parser("quickstart", help="Print a guided first-scan walkthrough")

    login_p = sub.add_parser("login-test", help="Verify an auth.json works before scanning")
    login_p.add_argument("target")
    login_p.add_argument("--auth", required=True)

    return parser


def main(argv=None) -> int:
    print_banner()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        setup_logging(verbose=args.verbose)
        if args.fast and args.deep:
            logging.error("--fast and --deep are mutually exclusive. Choose one.")
            return 1
        if not _confirm_authorization(args.i_have_permission):
            logging.error("Authorization not confirmed. Aborting.")
            return 1

        auth = load_auth(args.auth) if args.auth else None
        mode = "fast" if args.fast else "deep" if args.deep else "normal"
        config = ScanConfig(
            url=args.target, mode=mode, verbose=args.verbose, explain=args.explain,
            concurrency=args.concurrency, delay=args.delay, max_depth=args.max_depth,
            max_pages=args.max_pages, enable_idor=args.enable_idor, auth=auth,
            i_have_permission=args.i_have_permission,
        )
        report = run_scan(config)
        return 0 if report else 1

    elif args.command == "add":
        setup_logging()
        return 0 if add_payload(args.type, args.payload) else 1

    elif args.command == "list":
        list_payloads()
        return 0

    elif args.command == "learn":
        print_topic(args.topic)
        return 0

    elif args.command == "quickstart":
        print_quickstart()
        return 0

    elif args.command == "login-test":
        setup_logging()
        return 0 if login_test(args.auth, args.target) else 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
