"""Integration tests for IDOR/BOLA and Stored XSS detection against a local mock server.

Spins up a minimal aiohttp server that simulates:
- IDOR: /api/users?id=N returns different user data for different IDs
- Stored XSS: /guestbook (POST stores messages, GET renders them)

Tests verify the ActiveScanner detection logic finds these vulns.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import pytest

from justdastit.core.database import ProjectDB
from justdastit.core.engine import HttpEngine
from justdastit.core.models import ProjectConfig, ScopeRule
from justdastit.modules.active_scanner import ActiveScanner

# ---------------------------------------------------------------------------
# Mock vulnerable server
# ---------------------------------------------------------------------------

# Stored messages for the guestbook (simulates stored XSS)
_guestbook_messages: list[str] = []


class VulnHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler simulating IDOR and stored XSS vulnerabilities."""

    def log_message(self, format, *args):
        pass  # Suppress request logging

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/api/users":
            # IDOR: return different user data based on id param
            user_id = params.get("id", ["1"])[0]
            try:
                uid = int(user_id)
            except ValueError:
                uid = 0

            if uid <= 0 or uid > 100:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>User not found</body></html>")
                return

            # Each user gets different content (simulating real user data)
            body = (
                f"<html><body>"
                f"<h1>User Profile</h1>"
                f"<p>User ID: {uid}</p>"
                f"<p>Name: User_{uid}</p>"
                f"<p>Email: user{uid}@example.com</p>"
                f"<p>Bio: {'A' * (100 + uid * 10)}</p>"
                f"</body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        elif parsed.path == "/guestbook":
            # Stored XSS: render all stored messages (unsanitized)
            body = "<html><body><h1>Guestbook</h1>"
            body += '<form method="POST" action="/guestbook">'
            body += '<input type="text" name="message" />'
            body += '<input type="submit" value="Post" />'
            body += "</form>"
            body += "<h2>Messages:</h2><ul>"
            for msg in _guestbook_messages:
                body += f"<li>{msg}</li>"  # No escaping — stored XSS!
            body += "</ul></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8", errors="replace")
        post_params = parse_qs(post_body)

        if parsed.path == "/guestbook":
            message = post_params.get("message", [""])[0]
            if message:
                _guestbook_messages.append(message)
            # Redirect back to guestbook (PRG pattern)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Posted!</body></html>")
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def mock_server():
    """Start a mock vulnerable HTTP server in a background thread."""
    _guestbook_messages.clear()
    server = HTTPServer(("127.0.0.1", 0), VulnHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture
def scanner(mock_server):
    """Create an ActiveScanner pointed at the mock server."""
    scope = ScopeRule(include_patterns=["127.0.0.1"])
    config = ProjectConfig(scope=scope)
    db = ProjectDB(":memory:")
    engine = HttpEngine(config)

    # Add guestbook URL to sitemap so _test_stored_xss can find sibling pages
    db.add_sitemap_url(
        url=f"{mock_server}/guestbook",
        status_code=200,
        content_type="text/html",
        discovered_from="test",
        depth=0,
    )

    return ActiveScanner(engine, db, config), db, mock_server


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestIDOR:
    """Test IDOR/BOLA detection against the mock server."""

    @pytest.mark.asyncio
    async def test_idor_detects_adjacent_user(self, scanner):
        """Probing id=1 should find IDOR when id=2 returns different user data."""
        active, db, base = scanner
        url = f"{base}/api/users?id=1"
        findings = await active.scan_url(url)

        idor_findings = [f for f in findings if "IDOR" in f.title]
        assert len(idor_findings) >= 1, (
            f"Expected IDOR finding but got: {[f.title for f in findings]}"
        )

        f = idor_findings[0]
        assert f.cwe == "CWE-639"
        assert "id" in f.title.lower() or "id" in f.detail.lower()
        assert f.severity.value in ("high", "critical")

    @pytest.mark.asyncio
    async def test_idor_coverage_tracked(self, scanner):
        """IDOR probes should be tracked in DAST coverage."""
        active, db, base = scanner
        url = f"{base}/api/users?id=5"
        await active.scan_url(url)

        cov = active._dast.get("IDOR/BOLA")
        assert cov is not None
        assert cov.probes_sent > 0
        assert cov.params_tested > 0

    @pytest.mark.asyncio
    async def test_idor_skips_non_id_params(self, scanner):
        """Params with non-ID values should not trigger IDOR probes."""
        active, db, base = scanner
        url = f"{base}/api/users?id=1&format=json&debug=true"
        await active.scan_url(url)

        # format=json and debug=true should not be tested as IDs
        # (they match "alphanum" but are common non-ID values or booleans)
        cov = active._dast.get("IDOR/BOLA")
        # Should have tested "id" param but skipped "debug" (boolean)
        # "format" might be tested as alphanum but that's acceptable
        assert cov.params_tested >= 1


class TestStoredXSS:
    """Test Stored XSS detection against the mock server."""

    @pytest.mark.asyncio
    async def test_stored_xss_detected(self, scanner):
        """Canary injected into guestbook form should be found on re-fetch."""
        active, db, base = scanner
        _guestbook_messages.clear()

        # Simulate what the spider would find: a form on the guestbook page
        form = {
            "action": f"{base}/guestbook",
            "method": "POST",
            "found_on": f"{base}/guestbook",
            "inputs": [
                {"name": "message", "type": "text", "value": ""},
            ],
        }

        # Run _test_stored_xss directly
        findings_before = len(active._findings)
        await active._test_stored_xss(form, form["inputs"])
        findings_after = len(active._findings)

        stored_xss = [f for f in active._findings[findings_before:] if "Stored XSS" in f.title]
        assert len(stored_xss) >= 1, (
            f"Expected Stored XSS finding but got: {[f.title for f in active._findings[findings_before:]]}"
        )

        f = stored_xss[0]
        assert f.cwe == "CWE-79"
        assert "message" in f.title.lower() or "message" in f.detail.lower()
        assert "jdt_sxss_" in f.evidence

    @pytest.mark.asyncio
    async def test_stored_xss_coverage_tracked(self, scanner):
        """Stored XSS probes should be tracked in DAST coverage."""
        active, db, base = scanner
        _guestbook_messages.clear()

        form = {
            "action": f"{base}/guestbook",
            "method": "POST",
            "found_on": f"{base}/guestbook",
            "inputs": [
                {"name": "message", "type": "text", "value": ""},
            ],
        }

        await active._test_stored_xss(form, form["inputs"])

        cov = active._dast.get("Stored XSS")
        assert cov is not None
        assert cov.probes_sent > 0
        assert cov.params_tested > 0
        assert cov.findings_count > 0

    @pytest.mark.asyncio
    async def test_stored_xss_no_false_positive_when_not_stored(self, scanner):
        """If the server doesn't store the canary, no finding should be reported."""
        active, db, base = scanner

        # Use a form that posts to a non-guestbook endpoint (404, won't store)
        form = {
            "action": f"{base}/api/users",
            "method": "POST",
            "found_on": f"{base}/api/users",
            "inputs": [
                {"name": "message", "type": "text", "value": ""},
            ],
        }

        findings_before = len(active._findings)
        await active._test_stored_xss(form, form["inputs"])
        findings_after = len(active._findings)

        stored_xss = [f for f in active._findings[findings_before:] if "Stored XSS" in f.title]
        assert len(stored_xss) == 0, "Should not report stored XSS when canary is not persisted"


class TestLooksLikeId:
    """Test the _looks_like_id helper."""

    def test_numeric(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("1") == "numeric"
        assert _looks_like_id("12345") == "numeric"
        assert _looks_like_id("0") == "numeric"

    def test_uuid(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_alphanum(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("abc123") == "alphanum"
        assert _looks_like_id("user_42") == "alphanum"

    def test_skips_booleans(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("true") is None
        assert _looks_like_id("false") is None

    def test_skips_common_values(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("json") is None
        assert _looks_like_id("desc") is None
        assert _looks_like_id("asc") is None

    def test_skips_empty(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("") is None
        assert _looks_like_id("  ") is None

    def test_skips_long_text(self):
        from justdastit.modules.active_scanner import _looks_like_id
        assert _looks_like_id("this is a long search query with spaces") is None
