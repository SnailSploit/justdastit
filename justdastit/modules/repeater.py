"""justdastit - Repeater module for replaying and modifying requests."""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core.database import ProjectDB
from ..core.engine import HttpEngine
from ..core.models import HttpRequest, HttpResponse, ProjectConfig


class Repeater:
    """Replay, modify, and compare HTTP requests."""

    def __init__(self, engine: HttpEngine, db: ProjectDB) -> None:
        self.engine = engine
        self.db = db
        self.history: list[tuple[HttpRequest, HttpResponse]] = []

    async def send(self, request: HttpRequest) -> HttpResponse:
        """Send a request and record it."""
        resp = await self.engine.send(request)
        self.history.append((request, resp))
        self.db.save_request_response(request, resp, tags=["repeater"])
        return resp

    async def replay(self, request_id: int) -> Optional[HttpResponse]:
        """Replay a request from the database by ID."""
        rr = self.db.get_request_response(request_id)
        if not rr:
            return None
        return await self.send(rr.request)

    async def send_modified(
        self,
        request: HttpRequest,
        *,
        method: Optional[str] = None,
        url: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
        add_headers: Optional[dict[str, str]] = None,
        remove_headers: Optional[list[str]] = None,
        params: Optional[dict[str, str]] = None,
    ) -> HttpResponse:
        """Send a modified copy of a request."""
        req = copy.deepcopy(request)

        if method:
            req.method = method
        if url:
            req.url = url
        if headers:
            req.headers = headers
        if body is not None:
            req.body = body
        if add_headers:
            req.headers.update(add_headers)
        if remove_headers:
            for h in remove_headers:
                req.headers.pop(h, None)
        if params:
            parsed = urlparse(req.url)
            existing = parse_qs(parsed.query)
            existing.update({k: [v] for k, v in params.items()})
            new_query = urlencode(existing, doseq=True)
            req.url = urlunparse(parsed._replace(query=new_query))

        return await self.send(req)

    async def compare(
        self,
        req_a: HttpRequest,
        req_b: HttpRequest,
    ) -> dict:
        """Send two requests and compare responses."""
        resp_a = await self.send(req_a)
        resp_b = await self.send(req_b)

        return {
            "a": {
                "status": resp_a.status_code,
                "length": resp_a.content_length,
                "time_ms": resp_a.elapsed_ms,
            },
            "b": {
                "status": resp_b.status_code,
                "length": resp_b.content_length,
                "time_ms": resp_b.elapsed_ms,
            },
            "same_status": resp_a.status_code == resp_b.status_code,
            "length_diff": abs(resp_a.content_length - resp_b.content_length),
            "time_diff_ms": abs(resp_a.elapsed_ms - resp_b.elapsed_ms),
        }

    @staticmethod
    def from_raw(raw: str) -> HttpRequest:
        """Parse a raw HTTP request string into an HttpRequest."""
        lines = raw.strip().split("\n")
        if not lines:
            raise ValueError("Empty request")

        # Parse request line
        parts = lines[0].strip().split(" ", 2)
        method = parts[0]
        path = parts[1] if len(parts) > 1 else "/"

        # Parse headers
        headers: dict[str, str] = {}
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start = i + 1
                break
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()

        # Build URL from Host header + path
        host = headers.get("Host", "localhost")
        scheme = "https" if "443" in host else "http"
        url = f"{scheme}://{host}{path}"

        # Parse body
        body = None
        if body_start < len(lines):
            body = "\n".join(lines[body_start:]).encode()

        return HttpRequest(method=method, url=url, headers=headers, body=body)
