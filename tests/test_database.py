"""Tests for justdastit.core.database."""

from __future__ import annotations

import pytest

from justdastit.core.database import ProjectDB
from justdastit.core.models import Finding, HttpRequest, HttpResponse, Severity


class TestProjectDB:
    def test_save_and_get_request(self, tmp_db: ProjectDB) -> None:
        req = HttpRequest(method="GET", url="https://example.com/test")
        req_id = tmp_db.save_request(req)
        assert req_id >= 1

        rows = tmp_db.get_requests()
        assert len(rows) == 1
        assert rows[0]["method"] == "GET"
        assert rows[0]["url"] == "https://example.com/test"

    def test_save_request_response(self, tmp_db: ProjectDB) -> None:
        req = HttpRequest(method="POST", url="https://example.com/api")
        resp = HttpResponse(status_code=200, body=b"OK")
        req_id = tmp_db.save_request_response(req, resp, tags=["test"])

        rr = tmp_db.get_request_response(req_id)
        assert rr is not None
        assert rr.request.method == "POST"
        assert rr.response is not None
        assert rr.response.status_code == 200
        assert rr.tags == ["test"]

    def test_save_finding(self, tmp_db: ProjectDB) -> None:
        finding = Finding(
            title="XSS Found",
            severity=Severity.HIGH,
            url="https://example.com/search",
            detail="Reflected XSS in search parameter",
            cwe="CWE-79",
        )
        fid = tmp_db.save_finding(finding)
        assert fid >= 1

        findings = tmp_db.get_findings()
        assert len(findings) == 1
        assert findings[0]["title"] == "XSS Found"
        assert findings[0]["severity"] == "high"

    def test_get_findings_by_severity(self, tmp_db: ProjectDB) -> None:
        for sev in [Severity.HIGH, Severity.HIGH, Severity.LOW]:
            tmp_db.save_finding(
                Finding(title="Test", severity=sev, url="https://example.com", detail="t")
            )

        high = tmp_db.get_findings(severity="high")
        assert len(high) == 2

        low = tmp_db.get_findings(severity="low")
        assert len(low) == 1

    def test_sitemap(self, tmp_db: ProjectDB) -> None:
        tmp_db.add_sitemap_url("https://example.com/page1", status_code=200, content_type="text/html")
        tmp_db.add_sitemap_url("https://example.com/page2", status_code=301)

        sitemap = tmp_db.get_sitemap()
        assert len(sitemap) == 2

        urls = tmp_db.get_sitemap_urls()
        assert len(urls) == 2

    def test_sitemap_dedup(self, tmp_db: ProjectDB) -> None:
        tmp_db.add_sitemap_url("https://example.com/page1")
        tmp_db.add_sitemap_url("https://example.com/page1")
        assert len(tmp_db.get_sitemap()) == 1

    def test_save_and_get_forms(self, tmp_db: ProjectDB) -> None:
        tmp_db.save_form(
            url="https://example.com/form",
            action="https://example.com/submit",
            method="POST",
            inputs=[{"name": "user", "type": "text"}, {"name": "pass", "type": "password"}],
            found_on="https://example.com/login",
        )
        forms = tmp_db.get_forms()
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        assert len(forms[0]["inputs"]) == 2

    def test_get_stats(self, tmp_db: ProjectDB) -> None:
        req = HttpRequest(method="GET", url="https://example.com")
        resp = HttpResponse(status_code=200)
        tmp_db.save_request_response(req, resp)
        tmp_db.add_sitemap_url("https://example.com")
        tmp_db.save_finding(
            Finding(title="Test", severity=Severity.HIGH, url="https://example.com", detail="t")
        )

        stats = tmp_db.get_stats()
        assert stats["total_requests"] == 1
        assert stats["sitemap_urls"] == 1
        assert stats["total_findings"] == 1
        assert stats["findings_by_severity"]["high"] == 1

    def test_get_requests_with_filter(self, tmp_db: ProjectDB) -> None:
        tmp_db.save_request(HttpRequest(method="GET", url="https://example.com/api/users"))
        tmp_db.save_request(HttpRequest(method="GET", url="https://example.com/login"))

        filtered = tmp_db.get_requests(url_filter="api")
        assert len(filtered) == 1
        assert "api" in filtered[0]["url"]

    def test_get_request_response_not_found(self, tmp_db: ProjectDB) -> None:
        assert tmp_db.get_request_response(9999) is None

    def test_clear_findings(self, tmp_db: ProjectDB) -> None:
        tmp_db.save_finding(
            Finding(title="Test", severity=Severity.INFO, url="https://example.com", detail="t")
        )
        assert len(tmp_db.get_findings()) == 1
        tmp_db.clear_findings()
        assert len(tmp_db.get_findings()) == 0

    def test_get_all_request_responses(self, tmp_db: ProjectDB) -> None:
        for i in range(3):
            req = HttpRequest(method="GET", url=f"https://example.com/page{i}")
            resp = HttpResponse(status_code=200)
            tmp_db.save_request_response(req, resp)

        all_rr = tmp_db.get_all_request_responses()
        assert len(all_rr) == 3
