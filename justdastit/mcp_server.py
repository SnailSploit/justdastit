"""justdastit - MCP Server for AI-driven DAST scanning."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from .core.database import ProjectDB
from .core.engine import HttpEngine
from .core.models import HttpRequest, ProjectConfig, ScopeRule
from .utils.decoder import DECODERS, ENCODERS, HASHERS, smart_decode

__all__ = ["create_server"]


def create_server(db_path: str = "justdastit.db") -> Any:
    """Create and configure the MCP server."""
    try:
        from fastmcp import FastMCP
    except ImportError:
        raise ImportError("fastmcp required. Install with: pip install justdastit[mcp]")

    mcp = FastMCP(
        "justdastit",
        instructions="justdastit DAST toolkit — spider, fuzz, scan, and analyze web targets.",
    )
    config = ProjectConfig(db_path=db_path)
    db = ProjectDB(db_path)

    @mcp.tool()
    async def spider(url: str, depth: int = 3, threads: int = 10, scope: str = "") -> str:
        """Crawl a target URL and discover pages, forms, endpoints.

        Args:
            url: Starting URL to crawl
            depth: Maximum crawl depth (default 3)
            threads: Concurrent requests (default 10)
            scope: Domain scope pattern (auto-detected from URL if empty)
        """
        from urllib.parse import urlparse

        from .modules.spider import Spider

        cfg = ProjectConfig(db_path=db_path)
        host = scope or (urlparse(url).hostname or "")
        cfg.scope = ScopeRule(include_patterns=[host])

        engine = HttpEngine(cfg)
        sp = Spider(engine, db, cfg)
        stats = await sp.crawl(start_urls=[url], max_depth=depth, concurrency=threads)
        await engine.close()

        forms_data = [
            {"action": f["action"], "method": f["method"],
             "inputs": [i["name"] for i in f["inputs"] if i["name"]]}
            for f in sp.forms_found[:50]
        ]

        return json.dumps({
            "urls_visited": stats["visited"],
            "links_found": stats["links_found"],
            "forms_found": len(sp.forms_found),
            "forms": forms_data,
        }, indent=2)

    @mcp.tool()
    async def fuzz(url: str, payloads: str = "xss", attack: str = "sniper", threads: int = 10) -> str:
        """Fuzz URL parameters with payloads.

        Args:
            url: Target URL with parameters (e.g. https://target.com/search?q=test)
            payloads: Payload type: sqli, xss, ssti, lfi, cmdi (or file path)
            attack: Attack mode: sniper, battering_ram, pitchfork, cluster_bomb
            threads: Concurrent requests
        """
        from .modules.intruder import BUILTIN_PAYLOADS, AttackType, Intruder, IntruderConfig

        engine = HttpEngine(config)
        intruder = Intruder(engine, db)

        base_req = HttpRequest(method="GET", url=url)
        positions = Intruder.auto_detect_positions(base_req)
        if not positions:
            return json.dumps({"error": "No fuzzable positions detected"})

        if payloads in BUILTIN_PAYLOADS:
            payload_list = BUILTIN_PAYLOADS[payloads]()
        else:
            return json.dumps({"error": f"Unknown payload type: {payloads}"})

        intruder_config = IntruderConfig(
            base_request=base_req,
            positions=positions,
            payloads=[payload_list],
            attack_type=AttackType(attack),
            concurrency=threads,
        )

        results = await intruder.attack(intruder_config)
        await engine.close()

        matched = [r for r in results if r.matched]
        return json.dumps({
            "total_requests": len(results),
            "matched": len(matched),
            "positions": [p.name for p in positions],
            "results": [
                {
                    "payload": r.payload,
                    "status": r.response.status_code,
                    "length": r.response.content_length,
                    "time_ms": r.response.elapsed_ms,
                    "matched": r.matched,
                }
                for r in results[:100]
            ],
        }, indent=2)

    @mcp.tool()
    async def scan_passive() -> str:
        """Run passive scanner on all captured HTTP traffic. Returns findings."""
        from .modules.scanner import PassiveScanner

        scanner = PassiveScanner(db)
        findings = scanner.scan_all_history()
        return json.dumps({
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings[:100]],
        }, indent=2)

    @mcp.tool()
    async def active_scan(threads: int = 10) -> str:
        """Run active scanner on all discovered endpoints. Sends attack payloads.

        Args:
            threads: Concurrent requests (default 10)
        """
        from .modules.active_scanner import ActiveScanner

        cfg = ProjectConfig(db_path=db_path)
        engine = HttpEngine(cfg)
        scanner = ActiveScanner(engine, db, cfg)
        result = await scanner.scan(concurrency=threads)
        await engine.close()

        return json.dumps({
            "requests_sent": result.requests_sent,
            "urls_tested": result.urls_tested,
            "findings": [f.to_dict() for f in result.findings[:100]],
            "elapsed_seconds": round(result.elapsed_seconds, 2),
        }, indent=2)

    @mcp.tool()
    async def repeat_request(request_id: int) -> str:
        """Replay a captured request from history.

        Args:
            request_id: The request ID from history to replay
        """
        from .modules.repeater import Repeater

        engine = HttpEngine(config)
        repeater = Repeater(engine, db)
        resp = await repeater.replay(request_id)
        await engine.close()

        if not resp:
            return json.dumps({"error": f"Request {request_id} not found"})

        return json.dumps({
            "status_code": resp.status_code,
            "content_length": resp.content_length,
            "elapsed_ms": resp.elapsed_ms,
            "headers": dict(resp.headers),
            "body_preview": resp.body.decode("utf-8", errors="replace")[:2000] if resp.body else None,
        }, indent=2)

    @mcp.tool()
    def decode_data(data: str, encoding: str = "") -> str:
        """Decode data. Leave encoding empty for smart auto-detection.

        Args:
            data: The data to decode
            encoding: Decoder type: url, b64, b64url, html, hex, unicode, json, jwt (empty for auto)
        """
        if encoding:
            if encoding not in DECODERS:
                return json.dumps({"error": f"Unknown decoder: {encoding}", "available": list(DECODERS.keys())})
            try:
                return json.dumps({"result": str(DECODERS[encoding](data))})
            except Exception as e:
                return json.dumps({"error": str(e)})
        results = smart_decode(data)
        return json.dumps({"decodings": [{"type": n, "result": str(d)} for n, d in results]}, indent=2)

    @mcp.tool()
    def encode_data(data: str, encoding: str) -> str:
        """Encode data with specified encoder.

        Args:
            data: The data to encode
            encoding: Encoder type: url, url-full, double-url, b64, b64url, html, hex, unicode, json
        """
        if encoding not in ENCODERS:
            return json.dumps({"error": f"Unknown encoder: {encoding}", "available": list(ENCODERS.keys())})
        return json.dumps({"result": ENCODERS[encoding](data)})

    @mcp.tool()
    def hash_data(data: str, algorithm: str = "") -> str:
        """Hash data. Leave algorithm empty for all algorithms.

        Args:
            data: The data to hash
            algorithm: Hash algorithm: md5, sha1, sha256, sha512 (empty for all)
        """
        if algorithm:
            if algorithm not in HASHERS:
                return json.dumps({"error": f"Unknown hash: {algorithm}"})
            return json.dumps({"result": HASHERS[algorithm](data)})
        return json.dumps({name: func(data) for name, func in HASHERS.items()}, indent=2)

    @mcp.tool()
    def get_findings(severity: str = "") -> str:
        """Get security findings from the database.

        Args:
            severity: Filter by severity: critical, high, medium, low, info (empty for all)
        """
        findings = db.get_findings(severity=severity or None)
        return json.dumps({"total": len(findings), "findings": findings[:100]}, indent=2, default=str)

    @mcp.tool()
    def get_history(limit: int = 50, url_filter: str = "") -> str:
        """Browse captured HTTP request history.

        Args:
            limit: Number of requests to return (default 50)
            url_filter: Filter by URL pattern
        """
        rows = db.get_requests(limit=limit, url_filter=url_filter)
        return json.dumps({
            "total": len(rows),
            "requests": [
                {"id": r["id"], "method": r["method"], "url": r["url"],
                 "tags": json.loads(r.get("tags", "[]"))}
                for r in rows
            ],
        }, indent=2)

    @mcp.tool()
    def get_sitemap() -> str:
        """Get discovered URL sitemap."""
        urls = db.get_sitemap()
        return json.dumps({
            "total": len(urls),
            "urls": [
                {"url": u["url"], "status_code": u.get("status_code"),
                 "content_type": u.get("content_type", "")[:50]}
                for u in urls[:500]
            ],
        }, indent=2)

    return mcp
