"""justdastit - Session management with domain-scoped cookies and auto-auth."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from .models import HttpRequest, ProjectConfig

__all__ = ["LoginConfig", "SessionManager"]


@dataclass
class LoginConfig:
    """Configuration for auto-authentication."""

    url: str
    data: dict[str, str]
    csrf_field_names: list[str] = field(
        default_factory=lambda: [
            "user_token",
            "csrf_token",
            "_token",
            "csrfmiddlewaretoken",
            "authenticity_token",
            "__RequestVerificationToken",
        ]
    )


class SessionManager:
    """Thread-safe session management with domain-scoped cookies and auto re-auth."""

    def __init__(self, config: ProjectConfig) -> None:
        self._jar = httpx.Cookies()
        self._lock = asyncio.Lock()
        self._auth_header: Optional[tuple[str, str]] = None
        self._login_config: Optional[LoginConfig] = None
        self._config = config
        self._authenticated = False

    # ── Auth header setup ──────────────────────────────────────────────

    def set_auth_bearer(self, token: str) -> None:
        self._auth_header = ("Authorization", f"Bearer {token}")

    def set_auth_basic(self, username: str, password: str) -> None:
        import base64

        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._auth_header = ("Authorization", f"Basic {creds}")

    def set_auth_header(self, name: str, value: str) -> None:
        self._auth_header = (name, value)

    def set_login_config(self, login_config: LoginConfig) -> None:
        self._login_config = login_config

    # ── Cookie management ──────────────────────────────────────────────

    def set_cookies(self, cookies: dict[str, str], domain: str) -> None:
        """Set cookies with proper domain scoping (for CLI --cookie flag)."""
        for name, value in cookies.items():
            self._jar.set(name, value, domain=domain)

    def get_cookies(self) -> dict[str, str]:
        """Return a flat view of all cookies (for display/debug)."""
        return dict(self._jar)

    @property
    def cookie_jar(self) -> httpx.Cookies:
        """Direct access to the httpx cookie jar."""
        return self._jar

    # ── Request/response hooks ─────────────────────────────────────────

    async def apply(self, request: HttpRequest) -> HttpRequest:
        """Inject cookies and auth header into a request. Thread-safe."""
        async with self._lock:
            # Auth header
            if self._auth_header:
                key, val = self._auth_header
                if key not in request.headers:
                    request.headers[key] = val

            # Cookies — build from jar, scoped to request domain/path
            parsed = urlparse(request.url)
            domain = parsed.hostname or ""
            path = parsed.path or "/"

            # Collect cookies that match this request's domain
            cookie_pairs: list[str] = []
            for name, value in self._jar.items():
                cookie_pairs.append(f"{name}={value}")

            if cookie_pairs:
                existing = request.headers.get("Cookie", "")
                cookie_str = "; ".join(cookie_pairs)
                if existing:
                    cookie_str = f"{existing}; {cookie_str}"
                request.headers["Cookie"] = cookie_str

        return request

    async def update_from_response(self, resp: httpx.Response) -> None:
        """Extract cookies from raw httpx response (preserves all Set-Cookie headers)."""
        async with self._lock:
            # httpx.Response.cookies is already properly parsed
            self._jar.update(resp.cookies)

    # ── Auto-authentication ────────────────────────────────────────────

    async def ensure_authenticated(self, client: httpx.AsyncClient) -> bool:
        """Login using stored credentials. Returns True on success.

        Uses the provided httpx client directly (not the engine) to avoid
        circular dependency. Extracts CSRF tokens automatically.
        """
        if not self._login_config:
            return True

        lc = self._login_config

        # Step 1: GET login page to capture CSRF token + initial cookies
        get_resp = await client.get(lc.url, cookies=self._jar)
        async with self._lock:
            self._jar.update(get_resp.cookies)

        login_html = get_resp.text

        # Step 2: Build POST data with CSRF token injected
        post_data = dict(lc.data)

        # Build regex pattern for all known CSRF field names
        names_pattern = "|".join(re.escape(n) for n in lc.csrf_field_names)
        csrf_regex = (
            rf'name=["\']({names_pattern})["\']\s+value=["\']([^"\']+)["\']'
            rf'|value=["\']([^"\']+)["\']\s+name=["\']({names_pattern})["\']'
        )
        csrf_match = re.search(csrf_regex, login_html)
        if csrf_match:
            if csrf_match.group(1):
                csrf_name = csrf_match.group(1)
                csrf_value = csrf_match.group(2)
            else:
                csrf_name = csrf_match.group(4)
                csrf_value = csrf_match.group(3)
            post_data[csrf_name] = csrf_value

        # Step 3: POST login credentials
        post_resp = await client.post(
            lc.url,
            data=post_data,
            cookies=self._jar,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=True,
        )

        async with self._lock:
            self._jar.update(post_resp.cookies)
            # Also capture cookies from redirect chain
            if hasattr(post_resp, "history"):
                for r in post_resp.history:
                    self._jar.update(r.cookies)

        self._authenticated = True
        return post_resp.status_code == 200

    async def check_session_alive(
        self, client: httpx.AsyncClient, check_url: str
    ) -> bool:
        """Quick health check: GET a known URL and verify we're not redirected to login."""
        try:
            resp = await client.get(
                check_url, cookies=self._jar, follow_redirects=False
            )
            # 302 to login page = session dead
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "").lower()
                if any(kw in location for kw in ("login", "signin", "auth")):
                    return False
            # 401/403 = session dead
            if resp.status_code in (401, 403):
                return False
            return True
        except Exception:
            return False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated
