"""justdastit - Core data models and types."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

__all__ = [
    "Finding",
    "HttpRequest",
    "HttpResponse",
    "ProjectConfig",
    "RequestMethod",
    "RequestResponse",
    "ScopeRule",
    "Severity",
]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RequestMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


@dataclass
class HttpRequest:
    """Captured HTTP request."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    timestamp: float = field(default_factory=time.time)
    id: Optional[int] = None

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"

    @property
    def content_hash(self) -> str:
        raw = f"{self.method}|{self.url}|{self.body or b''}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace") if self.body else None,
            "timestamp": self.timestamp,
        }

    def to_raw(self) -> str:
        """Render as raw HTTP request string."""
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{self.method} {path} HTTP/1.1"]
        if "Host" not in self.headers:
            lines.append(f"Host: {parsed.hostname}")
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        raw = "\r\n".join(lines) + "\r\n\r\n"
        if self.body:
            raw += self.body.decode("utf-8", errors="replace")
        return raw


@dataclass
class HttpResponse:
    """Captured HTTP response."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    elapsed_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    raw_headers: list[tuple[str, str]] = field(default_factory=list)

    @property
    def content_length(self) -> int:
        if self.body:
            return len(self.body)
        return int(self.headers.get("content-length", "0"))

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body.decode("utf-8", errors="replace") if self.body else None,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class RequestResponse:
    """Paired request/response record."""

    request: HttpRequest
    response: Optional[HttpResponse] = None
    id: Optional[int] = None
    tags: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class Finding:
    """Security finding / vulnerability."""

    title: str
    severity: Severity
    url: str
    detail: str
    evidence: str = ""
    request: Optional[HttpRequest] = None
    response: Optional[HttpResponse] = None
    cwe: Optional[str] = None
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "url": self.url,
            "detail": self.detail,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
        }


@dataclass
class ScopeRule:
    """Target scope definition."""

    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)

    def in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        for pattern in self.exclude_patterns:
            if pattern in host or pattern in url:
                return False
        if not self.include_patterns:
            return True
        for pattern in self.include_patterns:
            if pattern in host or pattern in url:
                return True
        return False


@dataclass
class ProjectConfig:
    """Project-level configuration."""

    name: str = "default"
    scope: ScopeRule = field(default_factory=ScopeRule)
    db_path: str = "justdastit.db"
    proxy_port: int = 8080
    proxy_host: str = "127.0.0.1"
    threads: int = 10
    timeout: float = 10.0
    user_agent: str = "justdastit/3.0"
    follow_redirects: bool = True
    max_depth: int = 5
    verify_ssl: bool = False
    delay_ms: float = 0.0
    auth_type: Optional[str] = None
    auth_value: Optional[str] = None
