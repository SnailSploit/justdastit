"""justdastit - Async HTTP client engine with SessionManager integration."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Optional

import httpx

from .models import HttpRequest, HttpResponse, ProjectConfig
from .session import SessionManager

__all__ = ["HttpEngine"]


class HttpEngine:
    """Async HTTP client for all modules. Delegates auth/cookies to SessionManager."""

    def __init__(
        self, config: ProjectConfig, session: Optional[SessionManager] = None
    ) -> None:
        self.config = config
        self.session = session or SessionManager(config)
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_delay: float = 0.0
        self._last_request_time: float = 0.0
        self._request_count: int = 0

    # ── Convenience auth/cookie methods (delegate to session) ──────────

    def set_auth_bearer(self, token: str) -> None:
        self.session.set_auth_bearer(token)

    def set_auth_basic(self, username: str, password: str) -> None:
        self.session.set_auth_basic(username, password)

    def set_auth_header(self, name: str, value: str) -> None:
        self.session.set_auth_header(name, value)

    def update_cookies(self, cookies: dict[str, str]) -> None:
        """Backwards-compatible cookie update. Infers domain from first cookie URL."""
        # Legacy callers don't provide domain — store without domain scoping
        for k, v in cookies.items():
            self.session.cookie_jar.set(k, v)

    def set_rate_limit(self, delay_ms: float) -> None:
        self._rate_delay = delay_ms / 1000.0

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout),
                follow_redirects=self.config.follow_redirects,
                verify=self.config.verify_ssl,
                headers={"User-Agent": self.config.user_agent},
                limits=httpx.Limits(
                    max_connections=self.config.threads,
                    max_keepalive_connections=max(1, self.config.threads // 2),
                ),
            )
        return self._client

    async def get_client(self) -> httpx.AsyncClient:
        """Public access to httpx client (for SessionManager auth flows)."""
        return await self._get_client()

    async def send(self, request: HttpRequest) -> HttpResponse:
        """Send an HTTP request and return the response."""
        if self._rate_delay > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < self._rate_delay:
                await asyncio.sleep(self._rate_delay - elapsed)

        # SessionManager injects cookies + auth headers
        await self.session.apply(request)
        client = await self._get_client()
        start = time.monotonic()
        self._last_request_time = start

        try:
            resp = await client.request(
                method=request.method,
                url=request.url,
                headers=request.headers,
                content=request.body,
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            # Preserve raw headers (multi-value, e.g. multiple Set-Cookie)
            raw_headers = list(resp.headers.multi_items())

            http_resp = HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
                elapsed_ms=round(elapsed_ms, 2),
                raw_headers=raw_headers,
            )

            # Update session cookies from raw httpx response (no dict collapse)
            await self.session.update_from_response(resp)

            self._request_count += 1
            return http_resp
        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000
            self._request_count += 1
            return HttpResponse(status_code=0, elapsed_ms=round(elapsed_ms, 2))
        except httpx.RequestError as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            self._request_count += 1
            return HttpResponse(
                status_code=-1,
                headers={"error": str(e)},
                elapsed_ms=round(elapsed_ms, 2),
            )

    async def send_batch(
        self,
        requests: list[HttpRequest],
        concurrency: int = 10,
        callback: Optional[Callable[..., Any]] = None,
    ) -> list[tuple[HttpRequest, HttpResponse]]:
        """Send multiple requests with concurrency control."""
        sem = asyncio.Semaphore(concurrency)
        results: list[tuple[HttpRequest, HttpResponse]] = []

        async def _send_one(req: HttpRequest) -> None:
            async with sem:
                resp = await self.send(req)
                results.append((req, resp))
                if callback:
                    await callback(req, resp)

        tasks = [asyncio.create_task(_send_one(r)) for r in requests]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    @property
    def request_count(self) -> int:
        return self._request_count

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
