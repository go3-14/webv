"""Load an auth.json file into an AuthConfig, and a standalone login check.

Example auth.json (static credential):
    {"cookie": "session=abc123"}

Example auth.json (form login, e.g. OWASP Juice Shop / DVWA style):
    {
        "login_url": "http://localhost:3000/rest/user/login",
        "username_field": "email",
        "password_field": "password",
        "username": "test@example.com",
        "password": "test1234",
        "success_indicator": "authentication"
    }
"""

import json
import logging

from .config import AuthConfig
from .http_client import WebvClient


def load_auth(path: str) -> AuthConfig:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return AuthConfig.from_dict(data)


def login_test(path: str, url: str) -> bool:
    """Standalone `webv login-test` command: verify auth.json actually works
    before running a full scan against `url`."""
    auth = load_auth(path)
    client = WebvClient(auth=auth)
    try:
        if not client.authenticated:
            logging.error("Authentication failed — see the warning above for details.")
            return False
        res, _ = client.get(url)
        if res is None:
            logging.error("Could not reach %s after authenticating.", url)
            return False
        logging.info("Authenticated session reached %s (HTTP %s).", url, res.status_code)
        return True
    finally:
        client.close()
