"""Tests for justdastit.modules.scanner (passive scanner)."""

from __future__ import annotations

import pytest

from justdastit.core.database import ProjectDB
from justdastit.core.models import HttpRequest, HttpResponse, Severity
from justdastit.modules.scanner import PassiveScanner


@pytest.fixture
def scanner(tmp_db: ProjectDB) -> PassiveScanner:
    return PassiveScanner(tmp_db)


class TestSecurityHeaders:
    def test_missing_hsts(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"<html></html>",
        )
        findings = scanner.scan(req, resp)
        titles = [f.title for f in findings]
        assert "Missing HSTS Header" in titles

    def test_missing_csp(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"<html></html>",
        )
        findings = scanner.scan(req, resp)
        titles = [f.title for f in findings]
        assert "Missing Content-Security-Policy" in titles

    def test_all_headers_present(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "text/html",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
            body=b"<html></html>",
        )
        findings = scanner._check_security_headers(req, resp)
        assert len(findings) == 0

    def test_skip_non_html(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/api")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=b'{"data": "test"}',
        )
        findings = scanner._check_security_headers(req, resp)
        assert len(findings) == 0


class TestInformationDisclosure:
    def test_sql_error(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/search")
        resp = HttpResponse(
            status_code=500,
            headers={"content-type": "text/html"},
            body=b"You have an error in your SQL syntax near 'test'",
        )
        findings = scanner._check_information_disclosure(req, resp)
        assert any("SQL Error" in f.title for f in findings)

    def test_stack_trace(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=500,
            headers={"content-type": "text/html"},
            body=b"Traceback (most recent call last): at module.function(file.py:42)",
        )
        findings = scanner._check_information_disclosure(req, resp)
        assert any("Stack Trace" in f.title for f in findings)

    def test_path_disclosure(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"Error in /home/user/app/views/index.py",
        )
        findings = scanner._check_information_disclosure(req, resp)
        assert any("Path Disclosure" in f.title for f in findings)


class TestSensitiveData:
    def test_api_key_exposure(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/config")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b'api_key: "sk-1234567890abcdef1234567890"',
        )
        findings = scanner._check_sensitive_data(req, resp)
        assert any("API Key" in f.title for f in findings)

    def test_jwt_in_response(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/api")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            body=b'{"token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123def456"}',
        )
        findings = scanner._check_sensitive_data(req, resp)
        assert any("JWT" in f.title for f in findings)

    def test_aws_key(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"AKIAIOSFODNN7EXAMPLE",
        )
        findings = scanner._check_sensitive_data(req, resp)
        assert any("AWS" in f.title for f in findings)


class TestCORS:
    def test_wildcard_with_credentials(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/api")
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "application/json",
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            body=b"{}",
        )
        findings = scanner._check_cors(req, resp)
        assert any("Wildcard with Credentials" in f.title for f in findings)
        assert findings[0].severity == Severity.HIGH

    def test_wildcard_without_credentials(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/api")
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "application/json",
                "access-control-allow-origin": "*",
            },
            body=b"{}",
        )
        findings = scanner._check_cors(req, resp)
        assert any("Wildcard Origin" in f.title for f in findings)

    def test_origin_reflection(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers={"Origin": "https://evil.com"},
        )
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "application/json",
                "access-control-allow-origin": "https://evil.com",
            },
            body=b"{}",
        )
        findings = scanner._check_cors(req, resp)
        assert any("Origin Reflection" in f.title for f in findings)


class TestCookieFlags:
    def test_missing_secure(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "text/html",
                "set-cookie": "session=abc123; Path=/; HttpOnly",
            },
            body=b"OK",
        )
        findings = scanner._check_cookie_flags(req, resp)
        assert any("Secure Flag" in f.title for f in findings)

    def test_missing_httponly(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "text/html",
                "set-cookie": "session=abc123; Path=/; Secure",
            },
            body=b"OK",
        )
        findings = scanner._check_cookie_flags(req, resp)
        assert any("HttpOnly Flag" in f.title for f in findings)

    def test_missing_samesite(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={
                "content-type": "text/html",
                "set-cookie": "session=abc123; Path=/; Secure; HttpOnly",
            },
            body=b"OK",
        )
        findings = scanner._check_cookie_flags(req, resp)
        assert any("SameSite" in f.title for f in findings)


class TestServerBanner:
    def test_version_disclosure(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html", "server": "Apache/2.4.41"},
            body=b"OK",
        )
        findings = scanner._check_server_banner(req, resp)
        assert any("Version Disclosure" in f.title for f in findings)

    def test_powered_by(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html", "x-powered-by": "PHP/7.4"},
            body=b"OK",
        )
        findings = scanner._check_server_banner(req, resp)
        assert any("Technology Stack" in f.title for f in findings)


class TestDebugEndpoints:
    def test_debug_accessible(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/debug")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"Debug info",
        )
        findings = scanner._check_debug_endpoints(req, resp)
        assert any("Debug/Admin" in f.title for f in findings)

    def test_debug_not_found(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/debug")
        resp = HttpResponse(
            status_code=404,
            headers={"content-type": "text/html"},
            body=b"Not Found",
        )
        findings = scanner._check_debug_endpoints(req, resp)
        assert len(findings) == 0


class TestJWTIssues:
    def test_none_algorithm(self, scanner: PassiveScanner) -> None:
        # JWT with alg:none -> eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}."

        req = HttpRequest(
            method="GET",
            url="https://example.com/api",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = HttpResponse(status_code=200, headers={"content-type": "application/json"}, body=b"{}")
        findings = scanner._check_jwt_issues(req, resp)
        assert any("'none' Algorithm" in f.title for f in findings)


class TestErrorMessages:
    def test_verbose_error(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=500,
            headers={"content-type": "text/html"},
            body=b"Fatal error: unhandled exception in module",
        )
        findings = scanner._check_error_messages(req, resp)
        assert any("Verbose Error" in f.title for f in findings)

    def test_no_error_on_200(self, scanner: PassiveScanner) -> None:
        req = HttpRequest(method="GET", url="https://example.com/")
        resp = HttpResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=b"All good",
        )
        findings = scanner._check_error_messages(req, resp)
        assert len(findings) == 0
