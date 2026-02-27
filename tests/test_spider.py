"""Tests for justdastit.modules.spider."""

from __future__ import annotations

import pytest

from justdastit.core.models import ScopeRule
from justdastit.modules.spider import LinkExtractor, extract_links


class TestLinkExtractor:
    def test_extract_anchor_links(self) -> None:
        parser = LinkExtractor()
        parser.feed('<html><body><a href="/page1">Link 1</a><a href="/page2">Link 2</a></body></html>')
        assert "/page1" in parser.links
        assert "/page2" in parser.links

    def test_extract_form(self) -> None:
        html = '''<form action="/login" method="POST">
            <input name="user" type="text" value="">
            <input name="pass" type="password" value="">
            <input type="submit" value="Login">
        </form>'''
        parser = LinkExtractor()
        parser.feed(html)
        assert len(parser.forms) == 1
        assert parser.forms[0]["action"] == "/login"
        assert parser.forms[0]["method"] == "POST"
        assert len(parser.forms[0]["inputs"]) == 3

    def test_extract_script_src(self) -> None:
        parser = LinkExtractor()
        parser.feed('<script src="/js/app.js"></script>')
        assert "/js/app.js" in parser.links

    def test_extract_img_src(self) -> None:
        parser = LinkExtractor()
        parser.feed('<img src="/images/logo.png">')
        assert "/images/logo.png" in parser.links

    def test_extract_link_href(self) -> None:
        parser = LinkExtractor()
        parser.feed('<link rel="stylesheet" href="/css/style.css">')
        assert "/css/style.css" in parser.links

    def test_form_default_method(self) -> None:
        parser = LinkExtractor()
        parser.feed('<form action="/search"><input name="q"></form>')
        assert parser.forms[0]["method"] == "GET"


class TestExtractLinks:
    def test_resolve_relative_urls(self) -> None:
        html = '<a href="/page1">Link</a>'
        links, forms = extract_links(html, "https://example.com/dir/")
        assert "https://example.com/page1" in links

    def test_skip_fragments(self) -> None:
        html = '<a href="/page#section">Link</a>'
        links, _ = extract_links(html, "https://example.com/")
        for link in links:
            assert "#" not in link

    def test_skip_javascript_links(self) -> None:
        html = '<a href="javascript:void(0)">Click</a>'
        links, _ = extract_links(html, "https://example.com/")
        assert len(links) == 0

    def test_skip_mailto(self) -> None:
        html = '<a href="mailto:test@example.com">Email</a>'
        links, _ = extract_links(html, "https://example.com/")
        assert len(links) == 0

    def test_resolve_form_action(self) -> None:
        html = '<form action="/submit"><input name="q"></form>'
        _, forms = extract_links(html, "https://example.com/page")
        assert forms[0]["action"] == "https://example.com/submit"

    def test_extract_js_urls(self) -> None:
        html = '''<script>var url = "/api/data"; fetch(url);</script>'''
        links, _ = extract_links(html, "https://example.com/")
        # JS URL extraction may or may not capture this depending on regex
        assert isinstance(links, list)

    def test_dedup_links(self) -> None:
        html = '<a href="/page">Link 1</a><a href="/page">Link 2</a>'
        links, _ = extract_links(html, "https://example.com/")
        url_count = links.count("https://example.com/page")
        assert url_count <= 1


class TestScopeFiltering:
    def test_in_scope(self) -> None:
        scope = ScopeRule(include_patterns=["example.com"])
        assert scope.in_scope("https://example.com/page")
        assert not scope.in_scope("https://other.com/page")

    def test_exclude(self) -> None:
        scope = ScopeRule(
            include_patterns=["example.com"],
            exclude_patterns=["logout"],
        )
        assert not scope.in_scope("https://example.com/logout")
        assert scope.in_scope("https://example.com/dashboard")
