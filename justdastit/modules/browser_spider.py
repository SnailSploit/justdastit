"""justdastit - Playwright-based spider for JavaScript-heavy / SPA targets."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional, Set
from urllib.parse import urljoin, urlparse

from ..core.database import ProjectDB
from ..core.models import HttpRequest, HttpResponse, ProjectConfig
from ..core.session import SessionManager

__all__ = ["BrowserSpider"]

# Logout keywords — never click/navigate to these
_LOGOUT_KEYWORDS = {"logout", "signout", "sign-out", "log-out", "disconnect"}

# Skip these extensions
_SKIP_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
    ".zip", ".tar", ".gz", ".mp3", ".mp4", ".avi",
}


def _should_crawl(url: str) -> bool:
    """Filter out non-crawlable URLs."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for kw in _LOGOUT_KEYWORDS:
        if kw in path:
            return False
    for ext in _SKIP_EXTENSIONS:
        if path.endswith(ext):
            return False
    return True


class BrowserSpider:
    """Playwright-based crawler for SPA and JavaScript-heavy applications."""

    def __init__(
        self,
        db: ProjectDB,
        config: ProjectConfig,
        session: Optional[SessionManager] = None,
    ) -> None:
        self.db = db
        self.config = config
        self.session = session
        self.visited: Set[str] = set()
        self.queued: Set[str] = set()
        self.forms_found: list[dict] = []
        self._stats = {"requests": 0, "links_found": 0, "forms_found": 0}

    async def crawl(
        self,
        start_urls: list[str],
        max_depth: Optional[int] = None,
        concurrency: int = 3,
        callback: Optional[Callable] = None,
    ) -> dict:
        """Crawl using headless Chromium via Playwright."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright not installed. Install with: pip install playwright && playwright install chromium"
            )

        max_depth = max_depth or self.config.max_depth

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=self.config.user_agent,
                ignore_https_errors=not self.config.verify_ssl,
            )

            # Inject session cookies into browser context
            if self.session:
                pw_cookies = self._session_to_playwright_cookies()
                if pw_cookies:
                    await context.add_cookies(pw_cookies)

            # Intercept network requests to capture API calls
            captured_requests: list[tuple[str, str]] = []  # (method, url)

            sem = asyncio.Semaphore(concurrency)

            async def crawl_page(url: str, depth: int) -> list[tuple[str, int]]:
                """Visit a single page, extract links/forms, return new URLs to crawl."""
                if url in self.visited or depth > max_depth:
                    return []
                if not self.config.scope.in_scope(url):
                    return []

                self.visited.add(url)
                new_urls: list[tuple[str, int]] = []

                async with sem:
                    page = await context.new_page()

                    # Capture XHR/fetch requests
                    page_requests: list[tuple[str, str]] = []

                    def on_request(request):
                        req_url = request.url
                        if self.config.scope.in_scope(req_url) and _should_crawl(req_url):
                            page_requests.append((request.method, req_url))

                    page.on("request", on_request)

                    try:
                        response = await page.goto(url, wait_until="networkidle", timeout=15000)

                        if response:
                            status = response.status
                            ct = response.headers.get("content-type", "")
                            self._stats["requests"] += 1

                            # Save to DB
                            body = await page.content()
                            resp_obj = HttpResponse(
                                status_code=status,
                                headers=dict(response.headers),
                                body=body.encode("utf-8"),
                            )
                            req_obj = HttpRequest(method="GET", url=url)
                            self.db.save_request_response(req_obj, resp_obj, tags=["browser-spider"])
                            self.db.add_sitemap_url(
                                url=url,
                                status_code=status,
                                content_type=ct,
                                discovered_from="browser-spider",
                                depth=depth,
                            )

                            if callback:
                                await callback(url, resp_obj, depth)

                        # Extract links from the live DOM (after JS execution)
                        links = await page.evaluate("""() => {
                            const links = new Set();
                            // <a> tags
                            document.querySelectorAll('a[href]').forEach(a => {
                                links.add(a.href);
                            });
                            // router links (Angular, React, Vue)
                            document.querySelectorAll('[routerlink], [ng-href], [data-href]').forEach(el => {
                                const href = el.getAttribute('routerlink') ||
                                             el.getAttribute('ng-href') ||
                                             el.getAttribute('data-href');
                                if (href) links.add(new URL(href, location.href).href);
                            });
                            return [...links];
                        }""")

                        # Extract forms from live DOM
                        forms = await page.evaluate("""() => {
                            const forms = [];
                            document.querySelectorAll('form').forEach(form => {
                                const inputs = [];
                                form.querySelectorAll('input, select, textarea').forEach(el => {
                                    inputs.push({
                                        name: el.name || '',
                                        type: el.type || 'text',
                                        value: el.value || '',
                                    });
                                });
                                forms.push({
                                    action: form.action || location.href,
                                    method: (form.method || 'GET').toUpperCase(),
                                    inputs: inputs,
                                });
                            });
                            return forms;
                        }""")

                        # Process extracted links
                        for link in links:
                            link = link.split("#")[0]
                            if (
                                link
                                and link not in self.visited
                                and link not in self.queued
                                and self.config.scope.in_scope(link)
                                and _should_crawl(link)
                            ):
                                self.queued.add(link)
                                new_urls.append((link, depth + 1))
                                self._stats["links_found"] += 1

                        # Process forms
                        for form in forms:
                            form["found_on"] = url
                            self.forms_found.append(form)
                            self._stats["forms_found"] += 1
                            # Save form to DB
                            self.db.save_form(form)

                        # Process captured XHR/fetch URLs
                        for method, req_url in page_requests:
                            clean = req_url.split("#")[0]
                            if clean not in self.visited and clean not in self.queued:
                                self.queued.add(clean)
                                self.db.add_sitemap_url(
                                    url=clean,
                                    status_code=200,
                                    content_type="application/json",
                                    discovered_from=url,
                                    depth=depth,
                                )
                                if self.config.scope.in_scope(clean) and _should_crawl(clean):
                                    new_urls.append((clean, depth + 1))

                        # Try clicking interactive elements to discover more routes
                        try:
                            clickables = await page.query_selector_all(
                                'button:not([type="submit"]), [role="button"], [onclick], '
                                '.nav-link, .menu-item, [class*="tab"], [class*="btn"]'
                            )
                            for el in clickables[:10]:  # limit to 10 clicks per page
                                try:
                                    await el.click(timeout=2000)
                                    await page.wait_for_timeout(500)
                                    new_url = page.url.split("#")[0]
                                    if (
                                        new_url != url
                                        and new_url not in self.visited
                                        and new_url not in self.queued
                                        and self.config.scope.in_scope(new_url)
                                        and _should_crawl(new_url)
                                    ):
                                        self.queued.add(new_url)
                                        new_urls.append((new_url, depth + 1))
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    except Exception:
                        pass
                    finally:
                        await page.close()

                return new_urls

            # BFS crawl
            current_level = [(url, 0) for url in start_urls if self.config.scope.in_scope(url)]
            for url, _ in current_level:
                self.queued.add(url)

            while current_level:
                # Process current level in parallel (bounded by semaphore)
                tasks = [
                    asyncio.create_task(crawl_page(url, depth))
                    for url, depth in current_level
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                next_level: list[tuple[str, int]] = []
                for result in results:
                    if isinstance(result, list):
                        next_level.extend(result)

                current_level = next_level

            await browser.close()

        return self.stats

    def _session_to_playwright_cookies(self) -> list[dict]:
        """Convert SessionManager cookies to Playwright format."""
        if not self.session:
            return []
        cookies = []
        for name, value in self.session.cookie_jar.items():
            cookies.append({
                "name": name,
                "value": value,
                "domain": "localhost",  # will be overridden by actual domain
                "path": "/",
            })
        return cookies

    @property
    def stats(self) -> dict:
        return {
            **self._stats,
            "visited": len(self.visited),
            "queued": len(self.queued),
            "forms": len(self.forms_found),
        }
