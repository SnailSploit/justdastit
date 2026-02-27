"""Shared test fixtures for justdastit test suite."""

from __future__ import annotations

import os
import tempfile
from typing import Generator

import pytest

from justdastit.core.database import ProjectDB
from justdastit.core.engine import HttpEngine
from justdastit.core.models import (
    Finding,
    HttpRequest,
    HttpResponse,
    ProjectConfig,
    RequestResponse,
    ScopeRule,
    Severity,
)


@pytest.fixture
def tmp_db(tmp_path: object) -> Generator[ProjectDB, None, None]:
    """Temporary SQLite database for testing."""
    db_path = os.path.join(str(tmp_path), "test.db")
    db = ProjectDB(db_path)
    yield db
    db.close()


@pytest.fixture
def config() -> ProjectConfig:
    """Default test configuration."""
    return ProjectConfig(
        name="test-project",
        timeout=5.0,
        threads=5,
        user_agent="justdastit-test/1.0",
        verify_ssl=False,
    )


@pytest.fixture
def sample_request() -> HttpRequest:
    """Sample HTTP request."""
    return HttpRequest(
        method="GET",
        url="https://example.com/search?q=test&page=1",
        headers={"User-Agent": "test", "Host": "example.com"},
    )


@pytest.fixture
def sample_post_request() -> HttpRequest:
    """Sample POST request with form body."""
    return HttpRequest(
        method="POST",
        url="https://example.com/login",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "example.com",
        },
        body=b"username=admin&password=test123",
    )


@pytest.fixture
def sample_json_request() -> HttpRequest:
    """Sample POST request with JSON body."""
    return HttpRequest(
        method="POST",
        url="https://example.com/api/users",
        headers={
            "Content-Type": "application/json",
            "Host": "example.com",
        },
        body=b'{"name": "test", "email": "test@example.com"}',
    )


@pytest.fixture
def sample_cookie_request() -> HttpRequest:
    """Sample request with cookies."""
    return HttpRequest(
        method="GET",
        url="https://example.com/dashboard",
        headers={
            "Cookie": "session=abc123; user=admin",
            "Host": "example.com",
        },
    )


@pytest.fixture
def sample_response() -> HttpResponse:
    """Sample HTTP response with HTML."""
    return HttpResponse(
        status_code=200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/7.4",
        },
        body=b"<html><body><h1>Hello World</h1></body></html>",
        elapsed_ms=42.5,
    )


@pytest.fixture
def sample_response_missing_headers() -> HttpResponse:
    """Response missing security headers (for scanner tests)."""
    return HttpResponse(
        status_code=200,
        headers={
            "content-type": "text/html; charset=utf-8",
        },
        body=b"<html><body>Test</body></html>",
        elapsed_ms=20.0,
    )


@pytest.fixture
def sample_response_with_cookies() -> HttpResponse:
    """Response with Set-Cookie headers."""
    return HttpResponse(
        status_code=200,
        headers={
            "content-type": "text/html",
            "set-cookie": "session=xyz789; Path=/",
        },
        body=b"<html><body>Logged in</body></html>",
        elapsed_ms=30.0,
    )


@pytest.fixture
def sample_response_cors_wildcard() -> HttpResponse:
    """Response with CORS wildcard."""
    return HttpResponse(
        status_code=200,
        headers={
            "content-type": "application/json",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        },
        body=b'{"data": "sensitive"}',
        elapsed_ms=15.0,
    )


@pytest.fixture
def sample_response_sql_error() -> HttpResponse:
    """Response with SQL error disclosure."""
    return HttpResponse(
        status_code=500,
        headers={"content-type": "text/html"},
        body=b"<html>Error: You have an error in your SQL syntax near 'test' at line 1</html>",
        elapsed_ms=50.0,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Sample security finding."""
    return Finding(
        title="Missing HSTS Header",
        severity=Severity.MEDIUM,
        url="https://example.com/",
        detail="The response is missing the strict-transport-security header.",
        cwe="CWE-319",
    )
