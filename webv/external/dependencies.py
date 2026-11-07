"""Checks for optional external binaries/packages — all degrade gracefully."""

import logging
import shutil


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def check_external_tools() -> dict:
    status = {"nmap": check_tool("nmap"), "nikto": check_tool("nikto")}
    try:
        import playwright  # noqa: F401
        status["playwright"] = True
    except ImportError:
        status["playwright"] = False
    missing = [k for k, v in status.items() if not v and k != "playwright"]
    if missing:
        logging.warning(
            "Missing optional external tools: %s. Install with: sudo apt install %s "
            "(skipping the checks that need them — everything else still runs).",
            ", ".join(missing), " ".join(missing),
        )
    return status
