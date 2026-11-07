"""Scan configuration — one place that holds every knob the CLI exposes."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AuthConfig:
    """How to authenticate before scanning.

    Exactly one mode is normally set:
      - cookie / header: a static credential applied to every request.
      - login_url + a form-login block: webv POSTs once and reuses the
        resulting session cookie for the rest of the scan.
    """
    cookie: Optional[str] = None
    header_name: Optional[str] = None
    header_value: Optional[str] = None
    login_url: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    extra_fields: dict = field(default_factory=dict)
    # Text that must appear in the response after login to call it successful.
    success_indicator: Optional[str] = None

    @property
    def is_form_login(self) -> bool:
        return bool(self.login_url and self.username_field and self.password_field)

    @property
    def is_static(self) -> bool:
        return bool(self.cookie or (self.header_name and self.header_value))

    @classmethod
    def from_dict(cls, data: dict) -> "AuthConfig":
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


@dataclass
class ScanConfig:
    url: str
    mode: str = "normal"  # "fast" | "normal" | "deep"
    verbose: bool = False
    explain: bool = False
    concurrency: int = 5
    delay: float = 0.0
    max_depth: int = 2
    max_pages: int = 25
    checks: Optional[set] = None  # None == run everything enabled for the mode
    enable_idor: bool = False
    use_playwright: bool = False
    auth: Optional[AuthConfig] = None
    i_have_permission: bool = False

    @property
    def is_fast(self) -> bool:
        return self.mode == "fast"

    @property
    def is_deep(self) -> bool:
        return self.mode == "deep"

    def check_enabled(self, name: str) -> bool:
        return self.checks is None or name in self.checks
