"""Tests for justdastit.core.models."""

from __future__ import annotations

import time

import pytest

from justdastit.core.models import (
    Finding,
    HttpRequest,
    HttpResponse,
    ProjectConfig,
    RequestResponse,
    ScopeRule,
    Severity,
)


class TestHttpRequest:
    def test_basic_properties(self, sample_request: HttpRequest) -> None:
        assert sample_request.method == "GET"
        assert sample_request.host == "example.com"
        assert sample_request.path == "/search"

    def test_content_hash_deterministic(self) -> None:
        req1 = HttpRequest(method="GET", url="https://example.com/test")
        req2 = HttpRequest(method="GET", url="https://example.com/test")
        assert req1.content_hash == req2.content_hash

    def test_content_hash_differs(self) -> None:
        req1 = HttpRequest(method="GET", url="https://example.com/a")
        req2 = HttpRequest(method="GET", url="https://example.com/b")
        assert req1.content_hash != req2.content_hash

    def test_to_dict(self, sample_request: HttpRequest) -> None:
        d = sample_request.to_dict()
        assert d["method"] == "GET"
        assert d["url"] == "https://example.com/search?q=test&page=1"
        assert d["headers"]["Host"] == "example.com"
        assert d["body"] is None

    def test_to_dict_with_body(self, sample_post_request: HttpRequest) -> None:
        d = sample_post_request.to_dict()
        assert d["body"] == "username=admin&password=test123"

    def test_to_raw(self, sample_request: HttpRequest) -> None:
        raw = sample_request.to_raw()
        assert "GET /search?q=test&page=1 HTTP/1.1" in raw
        assert "Host: example.com" in raw

    def test_to_raw_with_body(self, sample_post_request: HttpRequest) -> None:
        raw = sample_post_request.to_raw()
        assert "POST /login HTTP/1.1" in raw
        assert "username=admin&password=test123" in raw

    def test_default_timestamp(self) -> None:
        before = time.time()
        req = HttpRequest(method="GET", url="https://example.com")
        after = time.time()
        assert before <= req.timestamp <= after

    def test_path_no_path(self) -> None:
        req = HttpRequest(method="GET", url="https://example.com")
        assert req.path == "/"


class TestHttpResponse:
    def test_content_length_from_body(self, sample_response: HttpResponse) -> None:
        assert sample_response.content_length == len(sample_response.body or b"")

    def test_content_length_no_body(self) -> None:
        resp = HttpResponse(status_code=204, headers={"content-length": "0"})
        assert resp.content_length == 0

    def test_content_type(self, sample_response: HttpResponse) -> None:
        assert "text/html" in sample_response.content_type

    def test_to_dict(self, sample_response: HttpResponse) -> None:
        d = sample_response.to_dict()
        assert d["status_code"] == 200
        assert "content-type" in d["headers"]


class TestScopeRule:
    def test_empty_scope_allows_all(self) -> None:
        scope = ScopeRule()
        assert scope.in_scope("https://anything.com/page")

    def test_include_pattern(self) -> None:
        scope = ScopeRule(include_patterns=["example.com"])
        assert scope.in_scope("https://example.com/page")
        assert not scope.in_scope("https://other.com/page")

    def test_exclude_pattern(self) -> None:
        scope = ScopeRule(include_patterns=["example.com"], exclude_patterns=["logout"])
        assert scope.in_scope("https://example.com/dashboard")
        assert not scope.in_scope("https://example.com/logout")

    def test_wildcard_subdomain(self) -> None:
        scope = ScopeRule(include_patterns=["example.com"])
        assert scope.in_scope("https://sub.example.com/page")
        assert scope.in_scope("https://api.example.com/v1")

    def test_exclude_takes_priority(self) -> None:
        scope = ScopeRule(
            include_patterns=["example.com"],
            exclude_patterns=["admin"],
        )
        assert not scope.in_scope("https://example.com/admin/panel")


class TestSeverity:
    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_is_string(self) -> None:
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "high"


class TestFinding:
    def test_to_dict(self, sample_finding: Finding) -> None:
        d = sample_finding.to_dict()
        assert d["title"] == "Missing HSTS Header"
        assert d["severity"] == "medium"
        assert d["cwe"] == "CWE-319"

    def test_default_timestamp(self) -> None:
        f = Finding(
            title="Test",
            severity=Severity.INFO,
            url="https://example.com",
            detail="test",
        )
        assert f.timestamp > 0


class TestProjectConfig:
    def test_defaults(self) -> None:
        config = ProjectConfig()
        assert config.threads == 10
        assert config.timeout == 10.0
        assert config.verify_ssl is False
        assert config.follow_redirects is True
