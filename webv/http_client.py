"""Shared HTTP session used by the crawler and every check module.

One client == one cookie jar == one auth state, so an authenticated session
(static header/cookie or a form login) is applied once and reused everywhere.
Concurrency is a thread pool over this client rather than asyncio — simpler to
reason about for a learner-facing codebase, and plenty fast for scan traffic.
"""

import logging
import threading
import time

import httpx

from .config import AuthConfig


class Transcript:
    """A redacted-enough record of one request/response pair, for the report."""

    def __init__(self, request: httpx.Request, response: httpx.Response):
        self.method = request.method
        self.url = str(request.url)
        self.request_headers = dict(request.headers)
        self.status_code = response.status_code
        body = response.text
        self.response_snippet = body[:2000]

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "response_snippet": self.response_snippet,
        }


class WebvClient:
    def __init__(self, auth: AuthConfig | None = None, delay: float = 0.0, timeout: float = 10.0):
        self.delay = delay
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)
        self.authenticated = False
        if auth:
            self._apply_auth(auth)

    def _apply_auth(self, auth: AuthConfig) -> None:
        if auth.is_static:
            if auth.cookie:
                # Accepts "name=value" or a raw Cookie header value.
                for part in auth.cookie.split(";"):
                    if "=" in part:
                        k, v = part.strip().split("=", 1)
                        self.client.cookies.set(k, v)
            if auth.header_name and auth.header_value:
                self.client.headers[auth.header_name] = auth.header_value
            self.authenticated = True
            logging.info("Applied static auth credential to session.")
        elif auth.is_form_login:
            self._form_login(auth)

    def _form_login(self, auth: AuthConfig) -> None:
        payload = {auth.username_field: auth.username, auth.password_field: auth.password}
        payload.update(auth.extra_fields)
        try:
            res = self.client.post(auth.login_url, data=payload, timeout=10.0, follow_redirects=True)
            if auth.success_indicator and auth.success_indicator not in res.text:
                logging.error(
                    "Login submitted but success indicator %r not found in response — "
                    "session may not be authenticated.",
                    auth.success_indicator,
                )
                self.authenticated = False
                return
            self.authenticated = True
            logging.info("Form login succeeded (%s cookies set).", len(self.client.cookies))
        except httpx.RequestError as e:
            logging.error("Login request failed: %s", e)
            self.authenticated = False

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self.delay - (now - self._last_request_time)
            if wait > 0:
                time.sleep(wait)
            self._last_request_time = time.monotonic()

    def request(self, method: str, url: str, capture: bool = False, **kwargs):
        self._throttle()
        try:
            req = self.client.build_request(method, url, **kwargs)
            res = self.client.send(req)
            transcript = Transcript(req, res) if capture else None
            return res, transcript
        except httpx.RequestError as e:
            logging.debug("Request failed: %s %s -> %s", method, url, e)
            return None, None

    def get(self, url: str, capture: bool = False, **kwargs):
        return self.request("GET", url, capture=capture, **kwargs)

    def post(self, url: str, capture: bool = False, **kwargs):
        return self.request("POST", url, capture=capture, **kwargs)

    def close(self) -> None:
        self.client.close()
