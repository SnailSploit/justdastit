"""justdastit - Spider module for async crawling with scope control."""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Callable, Optional, Set
from urllib.parse import urljoin, urlparse

from ..core.database import ProjectDB
from ..core.engine import HttpEngine
from ..core.models import HttpRequest, HttpResponse, ProjectConfig, ScopeRule


class LinkExtractor(HTMLParser):
    """Extract links from HTML content."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)

        if tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"] or "")
        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attr_dict.get("name", ""),
                    "type": attr_dict.get("type", "text"),
                    "value": attr_dict.get("value", ""),
                }
            )
        elif tag in ("script", "link", "img", "iframe", "source", "video", "audio"):
            src = attr_dict.get("src") or attr_dict.get("href")
            if src:
                self.links.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


def extract_links(html: str, base_url: str) -> tuple[list[str], list[dict]]:
    """Extract and resolve links from HTML content."""
    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    # Resolve relative URLs
    resolved: list[str] = []
    for link in parser.links:
        link = link.strip()
        if not link or link.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        full_url = urljoin(base_url, link)
        # Strip fragments
        full_url = full_url.split("#")[0]
        if full_url:
            resolved.append(full_url)

    # Also extract from JS strings
    js_urls = re.findall(
        r'(?:href|src|action|url)\s*[=:]\s*["\']([^"\']+)["\']', html
    )
    for url in js_urls:
        if url.startswith(("http://", "https://", "/")):
            full = urljoin(base_url, url).split("#")[0]
            if full:
                resolved.append(full)

    # Resolve form actions
    for form in parser.forms:
        if form["action"]:
            form["action"] = urljoin(base_url, form["action"])

    return list(set(resolved)), parser.forms


class Spider:
    """Async web crawler with scope control and depth limiting."""

    def __init__(
        self,
        engine: HttpEngine,
        db: ProjectDB,
        config: ProjectConfig,
    ) -> None:
        self.engine = engine
        self.db = db
        self.config = config
        self.visited: Set[str] = set()
        self.queued: Set[str] = set()
        self.forms_found: list[dict] = []
        self.running = False
        self._stats = {"requests": 0, "links_found": 0, "forms_found": 0}

    async def crawl(
        self,
        start_urls: list[str],
        max_depth: Optional[int] = None,
        concurrency: int = 10,
        callback: Optional[Callable] = None,
    ) -> dict:
        """Start crawling from seed URLs."""
        self.running = True
        max_depth = max_depth or self.config.max_depth
        sem = asyncio.Semaphore(concurrency)

        queue: asyncio.Queue[tuple[str, int, str]] = asyncio.Queue()
        for url in start_urls:
            if self.config.scope.in_scope(url):
                await queue.put((url, 0, "seed"))
                self.queued.add(url)

        async def worker() -> None:
            while self.running:
                try:
                    url, depth, source = await asyncio.wait_for(queue.get(), timeout=5)
                except asyncio.TimeoutError:
                    break

                if url in self.visited or depth > max_depth:
                    queue.task_done()
                    continue

                async with sem:
                    self.visited.add(url)
                    req = HttpRequest(method="GET", url=url)

                    resp = await self.engine.send(req)
                    self._stats["requests"] += 1

                    if resp.status_code <= 0:
                        queue.task_done()
                        continue

                    # Save to DB
                    self.db.save_request_response(req, resp, tags=["spider"])
                    self.db.add_sitemap_url(
                        url=url,
                        status_code=resp.status_code,
                        content_type=resp.content_type,
                        discovered_from=source,
                        depth=depth,
                    )

                    if callback:
                        await callback(url, resp, depth)

                    # Extract links from HTML responses
                    ct = resp.content_type.lower()
                    if "html" in ct and resp.body:
                        html = resp.body.decode("utf-8", errors="replace")
                        links, forms = extract_links(html, url)
                        self._stats["links_found"] += len(links)

                        for form in forms:
                            form["found_on"] = url
                            self.forms_found.append(form)
                            self._stats["forms_found"] += 1

                        for link in links:
                            if (
                                link not in self.visited
                                and link not in self.queued
                                and self.config.scope.in_scope(link)
                                and self._should_crawl(link)
                            ):
                                self.queued.add(link)
                                await queue.put((link, depth + 1, url))

                    queue.task_done()

        # Run workers
        workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers, return_exceptions=True)

        self.running = False
        return self.stats

    def _should_crawl(self, url: str) -> bool:
        """Filter out non-crawlable URLs."""
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Skip logout/signout URLs — they kill sessions
        logout_keywords = {"logout", "signout", "sign-out", "log-out", "disconnect"}
        for kw in logout_keywords:
            if kw in path:
                return False

        # Skip common static extensions
        skip_ext = {
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
            ".zip", ".tar", ".gz", ".mp3", ".mp4", ".avi",
        }
        for ext in skip_ext:
            if path.endswith(ext):
                return False
        return True

    @property
    def stats(self) -> dict:
        return {
            **self._stats,
            "visited": len(self.visited),
            "queued": len(self.queued),
            "forms": len(self.forms_found),
        }

    def stop(self) -> None:
        self.running = False
