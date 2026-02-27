"""justdastit - Active scanner: auto-attacks injection points from spider output."""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..core.database import ProjectDB
from ..core.engine import HttpEngine
from ..core.models import Finding, HttpRequest, HttpResponse, ProjectConfig, Severity
from ..modules.scanner import PassiveScanner
from ..modules.spider import extract_links
from ..plugins.base import load_plugins

__all__ = ["ActiveScanner", "DastCoverage", "DAST_CATEGORIES", "ScanResult"]

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS = [
    r"(?i)you have an error in your sql syntax",
    r"(?i)warning.*?\bmysql",
    r"(?i)unclosed quotation mark",
    r"(?i)quoted string not properly terminated",
    r"(?i)pg_query\(\)|pg_exec\(\)|pg_send_query\(\)",
    r"(?i)PostgreSQL.*?ERROR",
    r"(?i)ORA-\d{5}",
    r"(?i)Oracle.*?Driver",
    r"(?i)Microsoft.*?ODBC.*?SQL Server",
    r"(?i)SQLSTATE\[",
    r"(?i)SQLite3?::(?:query|exec)",
    r"(?i)sqlite3\.OperationalError",
    r"(?i)microsoft jet database engine",
    r"(?i)javax\.persistence",
    r"(?i)Hibernate.*?Exception",
]

# Use large math expressions that won't appear naturally in HTML
# 1337*7331 = 9799447 — 7 digits, extremely unlikely in normal content
SSTI_PROBES = [
    ("{{1337*7331}}", "9799447"),
    ("${1337*7331}", "9799447"),
    ("<%= 1337*7331 %>", "9799447"),
    ("#{1337*7331}", "9799447"),
    ("{{7*'7777777'}}", "7777777777777777777"),  # Jinja2 string repeat — 19 chars
]

# Path traversal — must match multi-line OS file content, not single tokens
PATH_TRAVERSAL_MARKERS = [
    (r"root:[x*]:0:0:", "Unix /etc/passwd"),
    (r"\[extensions\]\r?\n", "Windows win.ini"),
    (r"\[fonts\]\r?\n", "Windows win.ini"),
    (r"\[boot loader\]\r?\n", "Windows boot.ini"),
]

# Use a 36-char unique canary that will never appear in normal HTML
CMDI_CANARY = "jdt_rce_e8f2a91c7b4d6053"
COMMAND_INJECTION_PROBES = [
    (";sleep 7", "timing"),
    ("|sleep 7", "timing"),
    ("$(sleep 7)", "timing"),
    ("`sleep 7`", "timing"),
    (f";echo {CMDI_CANARY}", CMDI_CANARY),
    (f"|echo {CMDI_CANARY}", CMDI_CANARY),
]

XSS_CANARY = "jdt9x<xss>7q2m"
XSS_REFLECTED_PATTERN = re.escape(XSS_CANARY)

# SSRF payloads targeting cloud metadata + internal services
SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "aws", ["ami-id", "instance-id", "iam"]),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp", ["attributes", "project-id"]),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure", ["compute", "vmId"]),
    ("http://127.0.0.1:80/", "localhost", []),
    ("http://[::1]/", "ipv6-localhost", []),
    ("http://0x7f000001/", "hex-localhost", []),
    ("http://2130706433/", "decimal-localhost", []),
]

# Timing thresholds (ms)
BLIND_TIMING_THRESHOLD = 6000  # must exceed baseline by 6s (was 4s — too loose)
BLIND_TIMING_SLEEP = 7         # sleep payload uses 7s

# ---------------------------------------------------------------------------
# Param name sanitizer — drops HTML-entity artifacts like "amp;page"
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Unescape HTML entities in URLs before parsing.

    Spider sometimes captures URLs with &amp; instead of &, producing phantom
    params like 'amp;page'.  Normalize before parsing.
    """
    return url.replace("&amp;", "&")


def _is_input_reflected(canary: str, body: str) -> bool:
    """Check if a canary only appears in input-reflection contexts.

    Returns True if every occurrence is just the server echoing back our
    input in URLs, HTML attributes, JSON state blobs, or script tags —
    not actual command/template execution output.
    """
    idx = 0
    while True:
        pos = body.find(canary, idx)
        if pos == -1:
            break

        # Check surrounding 200 chars for reflection indicators
        context = body[max(0, pos - 200):pos + len(canary) + 200]

        # 1. URL-encoded context (e.g. %3Becho%20canary in og:url)
        prefix = body[max(0, pos - 10):pos]
        if "%" in prefix:
            idx = pos + 1
            continue

        # 2. JSON value reflection (e.g. "param":"canary" in __NEXT_DATA__)
        if re.search(r'["\']:\s*["\'][^"\']*$', body[max(0, pos - 100):pos]):
            idx = pos + 1
            continue

        # 3. HTML attribute reflection (href="...canary", content="...canary")
        attr_start = body.rfind('"', max(0, pos - 500), pos)
        if attr_start != -1:
            before_quote = body[max(0, attr_start - 30):attr_start]
            if re.search(r'(?:href|src|content|action|url|canonical|value)\s*=\s*$', before_quote, re.IGNORECASE):
                idx = pos + 1
                continue

        # 4. Inside <script> tag with JSON-like structure
        script_start = body.rfind("<script", max(0, pos - 5000), pos)
        script_end = body.find("</script>", pos)
        if script_start != -1 and script_end != -1:
            # Inside a script tag — check if it's JSON data (NEXT_DATA, etc.)
            script_content = body[script_start:script_end]
            if "__NEXT_DATA__" in script_content or "application/json" in script_content:
                idx = pos + 1
                continue

        # Not a reflection — this looks like real output
        return False

    return True


def _clean_param_names(params: dict[str, list[str]]) -> dict[str, list[str]]:
    """Drop any param whose name starts with 'amp;' — artifact of HTML entity encoding."""
    return {k: v for k, v in params.items() if not k.startswith("amp;")}


@dataclass
class DastCoverage:
    """Tracks what DAST tests were performed per attack category."""

    probes_sent: int = 0
    params_tested: int = 0
    urls_tested: int = 0
    findings_count: int = 0

    def record(self, probes: int = 1, params: int = 0, urls: int = 0, findings: int = 0) -> None:
        self.probes_sent += probes
        self.params_tested += params
        self.urls_tested += urls
        self.findings_count += findings


# Attack category names
DAST_CATEGORIES = [
    "Reflected XSS",
    "SQL Injection (Error)",
    "SQL Injection (Blind/Time)",
    "Server-Side Template Injection",
    "Path Traversal",
    "Command Injection",
    "Open Redirect",
    "SSRF",
    "HTTP Method Tampering",
    "Form Injection",
]


@dataclass
class ScanResult:
    """Result of an active scan."""

    findings: list[Finding] = field(default_factory=list)
    requests_sent: int = 0
    urls_tested: int = 0
    elapsed_seconds: float = 0.0
    dast_coverage: dict[str, DastCoverage] = field(default_factory=dict)

    @property
    def total_probes(self) -> int:
        return sum(c.probes_sent for c in self.dast_coverage.values())

    @property
    def total_params_tested(self) -> int:
        return sum(c.params_tested for c in self.dast_coverage.values())


class ActiveScanner:
    """Auto-attacks every discovered injection point from spider/sitemap data."""

    def __init__(
        self,
        engine: HttpEngine,
        db: ProjectDB,
        config: ProjectConfig,
        passive_scanner: Optional[PassiveScanner] = None,
    ) -> None:
        self.engine = engine
        self.db = db
        self.config = config
        self.passive = passive_scanner or PassiveScanner(db)
        self.plugins = load_plugins()
        self._findings: list[Finding] = []
        self._requests_sent = 0
        self._running = False
        # Dedup: set of (title, param, url_path_pattern)
        self._seen_findings: set[tuple[str, str]] = set()
        # DAST activity tracking per attack category
        self._dast: dict[str, DastCoverage] = {cat: DastCoverage() for cat in DAST_CATEGORIES}

    async def scan(
        self,
        concurrency: int = 10,
        callback: Optional[Callable[[Finding], None]] = None,
    ) -> ScanResult:
        """Run active scan against all discovered URLs and forms."""
        start = time.time()
        self._running = True
        self._findings = []
        self._requests_sent = 0
        self._seen_findings = set()
        self._dast = {cat: DastCoverage() for cat in DAST_CATEGORIES}

        sitemap_urls = self.db.get_sitemap_urls()
        forms = self.db.get_forms()
        sem = asyncio.Semaphore(concurrency)
        urls_tested = 0

        # Deduplicate URLs by (path, param_names) to avoid testing the same
        # endpoint pattern with different param values hundreds of times.
        tested_patterns: set[str] = set()

        async def scan_url(url: str) -> None:
            nonlocal urls_tested
            async with sem:
                if not self._running:
                    return
                if not self.config.scope.in_scope(url):
                    return

                # Deduplicate by path + sorted param names
                norm_url = _normalize_url(url)
                parsed = urlparse(norm_url)
                params = _clean_param_names(parse_qs(parsed.query, keep_blank_values=True))
                pattern_key = parsed.path + "?" + "&".join(sorted(params.keys()))
                if pattern_key in tested_patterns:
                    return
                tested_patterns.add(pattern_key)

                await self._test_url_params(url, callback)
                urls_tested += 1

        async def scan_form(form: dict) -> None:
            async with sem:
                if not self._running:
                    return
                action = form.get("action", "")
                if not action or not self.config.scope.in_scope(action):
                    return
                await self._test_form(form, callback)

        tasks = [asyncio.create_task(scan_url(url)) for url in sitemap_urls]
        tasks.extend([asyncio.create_task(scan_form(f)) for f in forms])

        await asyncio.gather(*tasks, return_exceptions=True)
        self._running = False

        return ScanResult(
            findings=self._findings,
            requests_sent=self._requests_sent,
            urls_tested=urls_tested,
            elapsed_seconds=time.time() - start,
            dast_coverage=dict(self._dast),
        )

    async def scan_url(
        self,
        url: str,
        callback: Optional[Callable[[Finding], None]] = None,
    ) -> list[Finding]:
        """Scan a single URL for vulnerabilities."""
        self._findings = []
        await self._test_url_params(url, callback)
        return self._findings

    # ------------------------------------------------------------------
    # Core test dispatcher
    # ------------------------------------------------------------------

    async def _test_url_params(
        self,
        url: str,
        callback: Optional[Callable[[Finding], None]] = None,
    ) -> None:
        """Test URL parameters for injection vulnerabilities."""
        url = _normalize_url(url)
        parsed = urlparse(url)
        params = _clean_param_names(parse_qs(parsed.query, keep_blank_values=True))
        if not params:
            return

        # Get baseline response for differential analysis
        baseline_req = HttpRequest(method="GET", url=url)
        baseline_resp = await self.engine.send(baseline_req)
        self._requests_sent += 1
        baseline_body = baseline_resp.body.decode("utf-8", errors="replace") if baseline_resp.body else ""
        self._run_passive(baseline_req, baseline_resp, callback)

        # Track URL-level coverage
        for cat in DAST_CATEGORIES:
            if cat not in ("HTTP Method Tampering", "Form Injection"):
                self._dast[cat].urls_tested += 1

        for param_name in params:
            await self._test_reflected_xss(url, param_name, parsed, params, baseline_body, callback)
            await self._test_sqli_error(url, param_name, parsed, params, baseline_body, callback)
            await self._test_sqli_blind(url, param_name, parsed, params, callback)
            await self._test_ssti(url, param_name, parsed, params, baseline_body, callback)
            await self._test_path_traversal(url, param_name, parsed, params, baseline_body, callback)
            await self._test_command_injection(url, param_name, parsed, params, baseline_body, callback)
            await self._test_open_redirect(url, param_name, parsed, params, callback)
            await self._test_ssrf(url, param_name, parsed, params, baseline_body, callback)

        # Run plugins
        base_req = HttpRequest(method="GET", url=url)
        for plugin in self.plugins:
            try:
                plugin_findings = await plugin.active_check(base_req, self.engine)
                for f in plugin_findings:
                    self._add_finding(f, callback)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Form testing
    # ------------------------------------------------------------------

    async def _fetch_fresh_form(self, form: dict) -> Optional[dict]:
        """Re-fetch the page where a form lives to get fresh CSRF tokens and inputs."""
        found_on = form.get("found_on", form.get("action", ""))
        if not found_on:
            return None
        resp = await self.engine.send(HttpRequest(method="GET", url=found_on))
        self._requests_sent += 1
        if resp.status_code != 200 or not resp.body:
            return None
        html = resp.body.decode("utf-8", errors="replace")
        _, forms = extract_links(html, found_on)
        if not forms:
            return None
        # Match by action URL
        target_action = form.get("action", "")
        for f in forms:
            if f.get("action") == target_action:
                return f
        # Fallback: return first form on the page
        return forms[0]

    async def check_session_alive(self, check_url: str) -> bool:
        """Quick health check: GET a known URL, verify we're not redirected to login."""
        try:
            req = HttpRequest(method="GET", url=check_url)
            resp = await self.engine.send(req)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "").lower()
                if any(kw in location for kw in ("login", "signin", "auth")):
                    return False
            if resp.status_code in (401, 403):
                return False
            return True
        except Exception:
            return False

    async def _test_form(
        self,
        form: dict,
        callback: Optional[Callable[[Finding], None]] = None,
    ) -> None:
        """Test form inputs for injection vulnerabilities."""
        # Re-fetch form to get fresh CSRF tokens
        fresh = await self._fetch_fresh_form(form)
        if fresh is not None:
            form = fresh

        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Get baseline
        form_data_baseline = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}
        if method == "POST":
            bl_body = urlencode(form_data_baseline).encode()
            bl_req = HttpRequest(method="POST", url=action, body=bl_body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            bl_query = urlencode(form_data_baseline)
            bl_url = urlunparse(urlparse(action)._replace(query=bl_query))
            bl_req = HttpRequest(method="GET", url=bl_url)
        bl_resp = await self.engine.send(bl_req)
        self._requests_sent += 1
        baseline_body = bl_resp.body.decode("utf-8", errors="replace") if bl_resp.body else ""

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue

            self._dast["Form Injection"].urls_tested += 1
            for probe, detector in [
                (XSS_CANARY, "xss_reflect"),
                ("'", "sqli_error"),
                ("1' ORDER BY 100--", "sqli_error"),
                ("' OR '1'='1", "sqli_error"),
                ("{{1337*7331}}", "ssti"),
                (f"127.0.0.1;echo {CMDI_CANARY}", "cmdi"),
                (f"127.0.0.1|echo {CMDI_CANARY}", "cmdi"),
                (f"127.0.0.1$(echo {CMDI_CANARY})", "cmdi"),
            ]:
                form_data = {i.get("name", ""): i.get("value", "test") for i in inputs if i.get("name")}
                form_data[name] = probe

                if method == "POST":
                    body = urlencode(form_data).encode()
                    req = HttpRequest(method="POST", url=action, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    query = urlencode(form_data)
                    test_url = urlunparse(urlparse(action)._replace(query=query))
                    req = HttpRequest(method="GET", url=test_url)

                resp = await self.engine.send(req)
                self._requests_sent += 1
                self._dast["Form Injection"].record(probes=1, params=1)

                body_text = resp.body.decode("utf-8", errors="replace") if resp.body else ""
                if detector == "xss_reflect" and XSS_CANARY in body_text and XSS_CANARY not in baseline_body:
                    self._dast["Form Injection"].findings_count += 1
                    self._add_finding(Finding(
                        title=f"Reflected XSS in form input '{name}'",
                        severity=Severity.HIGH,
                        url=action,
                        detail=f"XSS canary reflected in response from form input '{name}'.",
                        evidence=XSS_CANARY,
                        cwe="CWE-79",
                        request=req,
                        response=resp,
                    ), callback)
                elif detector == "sqli_error":
                    for pattern in SQL_ERROR_PATTERNS:
                        match = re.search(pattern, body_text)
                        if match and not re.search(pattern, baseline_body):
                            self._dast["Form Injection"].findings_count += 1
                            self._add_finding(Finding(
                                title=f"SQL Injection in form input '{name}'",
                                severity=Severity.HIGH,
                                url=action,
                                detail=f"SQL error triggered via '{probe}' in form input '{name}'.",
                                evidence=match.group(0)[:200],
                                cwe="CWE-89",
                                request=req,
                                response=resp,
                            ), callback)
                            break
                elif detector == "ssti" and "9799447" in body_text and "9799447" not in baseline_body:
                    self._dast["Form Injection"].findings_count += 1
                    self._add_finding(Finding(
                        title=f"Server-Side Template Injection in form input '{name}'",
                        severity=Severity.HIGH,
                        url=action,
                        detail=f"Template expression evaluated in form input '{name}'.",
                        evidence="{{1337*7331}} -> 9799447",
                        cwe="CWE-1336",
                        request=req,
                        response=resp,
                    ), callback)
                elif detector == "cmdi" and CMDI_CANARY in body_text and CMDI_CANARY not in baseline_body:
                    if not _is_input_reflected(CMDI_CANARY, body_text):
                        self._dast["Form Injection"].findings_count += 1
                        self._add_finding(Finding(
                            title=f"Command Injection in form input '{name}'",
                            severity=Severity.CRITICAL,
                            url=action,
                            detail=f"OS command output canary found in response from form input '{name}'.",
                            evidence=CMDI_CANARY,
                            cwe="CWE-78",
                            request=req,
                            response=resp,
                        ), callback)

    # ------------------------------------------------------------------
    # Injection helpers
    # ------------------------------------------------------------------

    async def _inject_and_send(
        self,
        url: str,
        param_name: str,
        parsed: object,
        params: dict,
        payload: str,
    ) -> tuple[HttpRequest, HttpResponse]:
        """Inject payload into a URL parameter and send the request."""
        test_params = {k: v[:] for k, v in params.items()}
        test_params[param_name] = [payload]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))  # type: ignore[union-attr]
        req = HttpRequest(method="GET", url=test_url)
        resp = await self.engine.send(req)
        self._requests_sent += 1
        return req, resp

    # ------------------------------------------------------------------
    # Reflected XSS
    # ------------------------------------------------------------------

    async def _test_reflected_xss(
        self, url: str, param: str, parsed: object, params: dict,
        baseline_body: str, callback: Optional[Callable] = None,
    ) -> None:
        req, resp = await self._inject_and_send(url, param, parsed, params, XSS_CANARY)
        self._dast["Reflected XSS"].record(probes=1, params=1)
        body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
        # Only flag if canary appears in injected response but NOT in baseline
        if re.search(XSS_REFLECTED_PATTERN, body) and XSS_CANARY not in baseline_body:
            self._dast["Reflected XSS"].findings_count += 1
            self._add_finding(Finding(
                title=f"Reflected XSS via '{param}'",
                severity=Severity.HIGH,
                url=url,
                detail=f"XSS canary reflected unescaped in response for param '{param}'.",
                evidence=XSS_CANARY,
                cwe="CWE-79",
                request=req,
                response=resp,
            ), callback)

    # ------------------------------------------------------------------
    # SQL Injection — Error-Based
    # ------------------------------------------------------------------

    async def _test_sqli_error(
        self, url: str, param: str, parsed: object, params: dict,
        baseline_body: str, callback: Optional[Callable] = None,
    ) -> None:
        for payload in ["'", "' OR '1'='1", "1' ORDER BY 100--", "1 AND 1=CONVERT(int,(SELECT @@version))--"]:
            req, resp = await self._inject_and_send(url, param, parsed, params, payload)
            self._dast["SQL Injection (Error)"].record(probes=1, params=1)
            body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
            for pattern in SQL_ERROR_PATTERNS:
                match = re.search(pattern, body)
                # Must NOT be in baseline — avoids flagging normal error text
                if match and not re.search(pattern, baseline_body):
                    self._dast["SQL Injection (Error)"].findings_count += 1
                    self._add_finding(Finding(
                        title=f"SQL Injection (Error-Based) via '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        detail=f"SQL error signature detected after injecting '{payload}' into '{param}'.",
                        evidence=match.group(0)[:200],
                        cwe="CWE-89",
                        request=req,
                        response=resp,
                    ), callback)
                    return

    # ------------------------------------------------------------------
    # SQL Injection — Blind (Time-Based)
    # ------------------------------------------------------------------

    async def _test_sqli_blind(
        self, url: str, param: str, parsed: object, params: dict,
        callback: Optional[Callable] = None,
    ) -> None:
        baseline_req, baseline_resp = await self._inject_and_send(url, param, parsed, params, "1")
        baseline_time = baseline_resp.elapsed_ms

        for payload in ["1' AND SLEEP(7)--", "1; WAITFOR DELAY '0:0:7'--", "1' OR pg_sleep(7)--"]:
            req, resp = await self._inject_and_send(url, param, parsed, params, payload)
            self._dast["SQL Injection (Blind/Time)"].record(probes=1, params=1)
            if resp.elapsed_ms > baseline_time + BLIND_TIMING_THRESHOLD:
                # Confirm with a second request to reduce false positives from network jitter
                req2, resp2 = await self._inject_and_send(url, param, parsed, params, payload)
                if resp2.elapsed_ms > baseline_time + BLIND_TIMING_THRESHOLD:
                    self._add_finding(Finding(
                        title=f"Blind SQL Injection (Time-Based) via '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        detail=f"Consistent time delay: baseline {baseline_time:.0f}ms vs {resp.elapsed_ms:.0f}ms / {resp2.elapsed_ms:.0f}ms with payload '{payload}'.",
                        evidence=f"Delay: {resp.elapsed_ms - baseline_time:.0f}ms (confirmed: {resp2.elapsed_ms - baseline_time:.0f}ms)",
                        cwe="CWE-89",
                        request=req,
                        response=resp,
                    ), callback)
                    return

    # ------------------------------------------------------------------
    # SSTI
    # ------------------------------------------------------------------

    async def _test_ssti(
        self, url: str, param: str, parsed: object, params: dict,
        baseline_body: str, callback: Optional[Callable] = None,
    ) -> None:
        for probe, expected in SSTI_PROBES:
            req, resp = await self._inject_and_send(url, param, parsed, params, probe)
            self._dast["Server-Side Template Injection"].record(probes=1, params=1)
            body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
            # Three conditions: (1) expected in body, (2) probe NOT in body (evaluated),
            # (3) expected NOT in baseline (differential)
            if expected in body and probe not in body and expected not in baseline_body:
                # Verify expected value isn't just input reflection
                # (e.g. Next.js reflecting the probe in __NEXT_DATA__)
                if not _is_input_reflected(expected, body):
                    self._add_finding(Finding(
                        title=f"Server-Side Template Injection via '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        detail=f"Template expression '{probe}' evaluated to '{expected}' in param '{param}'.",
                        evidence=f"{probe} -> {expected}",
                        cwe="CWE-1336",
                        request=req,
                        response=resp,
                    ), callback)
                    return

    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------

    async def _test_path_traversal(
        self, url: str, param: str, parsed: object, params: dict,
        baseline_body: str, callback: Optional[Callable] = None,
    ) -> None:
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
        ]
        for payload in payloads:
            req, resp = await self._inject_and_send(url, param, parsed, params, payload)
            self._dast["Path Traversal"].record(probes=1, params=1)
            body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
            for marker, desc in PATH_TRAVERSAL_MARKERS:
                match = re.search(marker, body)
                # Marker must appear in injected response AND NOT in baseline
                if match and not re.search(marker, baseline_body):
                    self._add_finding(Finding(
                        title=f"Path Traversal via '{param}'",
                        severity=Severity.HIGH,
                        url=url,
                        detail=f"File content marker ({desc}) found after injecting '{payload}' into '{param}'.",
                        evidence=match.group(0)[:200],
                        cwe="CWE-22",
                        request=req,
                        response=resp,
                    ), callback)
                    return

    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------

    async def _test_command_injection(
        self, url: str, param: str, parsed: object, params: dict,
        baseline_body: str, callback: Optional[Callable] = None,
    ) -> None:
        baseline_req, baseline_resp = await self._inject_and_send(url, param, parsed, params, "test")
        baseline_time = baseline_resp.elapsed_ms

        for payload, detection in COMMAND_INJECTION_PROBES:
            req, resp = await self._inject_and_send(url, param, parsed, params, payload)
            self._dast["Command Injection"].record(probes=1, params=1)
            body = resp.body.decode("utf-8", errors="replace") if resp.body else ""

            if detection == "timing":
                if resp.elapsed_ms > baseline_time + BLIND_TIMING_THRESHOLD:
                    # Confirm timing
                    req2, resp2 = await self._inject_and_send(url, param, parsed, params, payload)
                    if resp2.elapsed_ms > baseline_time + BLIND_TIMING_THRESHOLD:
                        self._add_finding(Finding(
                            title=f"Command Injection (Blind) via '{param}'",
                            severity=Severity.CRITICAL,
                            url=url,
                            detail=f"Consistent time delay with cmdi payload '{payload}'.",
                            evidence=f"Delay: {resp.elapsed_ms - baseline_time:.0f}ms (confirmed: {resp2.elapsed_ms - baseline_time:.0f}ms)",
                            cwe="CWE-78",
                            request=req,
                            response=resp,
                        ), callback)
                        return
            else:
                # Canary must appear in injected response AND NOT in baseline
                # AND must not be URL-reflected (e.g. in og:url, canonical meta tags)
                if detection in body and detection not in baseline_body:
                    if not _is_input_reflected(detection, body):
                        self._add_finding(Finding(
                            title=f"Command Injection via '{param}'",
                            severity=Severity.CRITICAL,
                            url=url,
                            detail=f"Command output canary found in response for param '{param}'.",
                            evidence=detection,
                            cwe="CWE-78",
                            request=req,
                            response=resp,
                        ), callback)
                        return

    # ------------------------------------------------------------------
    # Open Redirect
    # ------------------------------------------------------------------

    async def _test_open_redirect(
        self, url: str, param: str, parsed: object, params: dict,
        callback: Optional[Callable] = None,
    ) -> None:
        canary = "https://evil.snailsploit.test"
        req, resp = await self._inject_and_send(url, param, parsed, params, canary)
        self._dast["Open Redirect"].record(probes=1, params=1)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if canary in location:
                self._add_finding(Finding(
                    title=f"Open Redirect via '{param}'",
                    severity=Severity.MEDIUM,
                    url=url,
                    detail=f"Redirect to attacker-controlled domain via param '{param}'.",
                    evidence=f"Location: {location}",
                    cwe="CWE-601",
                    request=req,
                    response=resp,
                ), callback)

    # ------------------------------------------------------------------
    # SSRF
    # ------------------------------------------------------------------

    async def _test_ssrf(
        self, url: str, param: str, parsed: object, params: dict,
        baseline_body: str, callback: Optional[Callable] = None,
    ) -> None:
        """Test for SSRF via cloud metadata endpoints and internal IPs."""
        baseline_req, baseline_resp = await self._inject_and_send(url, param, parsed, params, "test")
        baseline_size = len(baseline_resp.body) if baseline_resp.body else 0
        baseline_status = baseline_resp.status_code

        for payload, provider, markers in SSRF_PAYLOADS:
            req, resp = await self._inject_and_send(url, param, parsed, params, payload)
            self._dast["SSRF"].record(probes=1, params=1)
            body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
            resp_size = len(resp.body) if resp.body else 0

            # Detection: response contains cloud metadata markers
            for marker in markers:
                if marker in body and marker not in baseline_body:
                    self._add_finding(Finding(
                        title=f"SSRF via '{param}' ({provider})",
                        severity=Severity.CRITICAL,
                        url=url,
                        detail=f"Cloud metadata content from {provider} returned via param '{param}' with payload '{payload}'.",
                        evidence=body[:300],
                        cwe="CWE-918",
                        request=req,
                        response=resp,
                    ), callback)
                    return

            # Detection: significant size change + different status (possible internal service)
            if (
                resp.status_code == 200
                and baseline_status != 200
                and resp_size > baseline_size + 100
            ):
                self._add_finding(Finding(
                    title=f"Possible SSRF via '{param}' ({provider})",
                    severity=Severity.HIGH,
                    url=url,
                    detail=f"Response status/size changed significantly with SSRF payload targeting {provider}.",
                    evidence=f"Baseline: {baseline_status}/{baseline_size}B → Injected: {resp.status_code}/{resp_size}B",
                    cwe="CWE-918",
                    request=req,
                    response=resp,
                ), callback)
                return

    # ------------------------------------------------------------------
    # HTTP Method Tampering
    # ------------------------------------------------------------------

    async def test_method_tampering(
        self,
        url: str,
        callback: Optional[Callable] = None,
    ) -> None:
        """Test an endpoint with alternate HTTP methods to detect access control bypass."""
        # Get baseline with GET
        get_req = HttpRequest(method="GET", url=url)
        get_resp = await self.engine.send(get_req)
        self._requests_sent += 1
        get_status = get_resp.status_code

        self._dast["HTTP Method Tampering"].urls_tested += 1
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]:
            req = HttpRequest(method=method, url=url)
            resp = await self.engine.send(req)
            self._requests_sent += 1
            self._dast["HTTP Method Tampering"].record(probes=1)

            if method == "TRACE" and resp.status_code == 200:
                body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
                if "TRACE" in body:
                    self._add_finding(Finding(
                        title="HTTP TRACE Method Enabled",
                        severity=Severity.MEDIUM,
                        url=url,
                        detail="TRACE method is enabled, potentially allowing Cross-Site Tracing (XST) attacks.",
                        evidence=f"TRACE response: {body[:200]}",
                        cwe="CWE-693",
                        request=req,
                        response=resp,
                    ), callback)

            elif method == "OPTIONS" and resp.status_code == 200:
                allow = resp.headers.get("allow", "")
                if allow and any(m in allow.upper() for m in ["PUT", "DELETE"]):
                    self._add_finding(Finding(
                        title="Dangerous HTTP Methods Allowed",
                        severity=Severity.MEDIUM,
                        url=url,
                        detail=f"OPTIONS reveals dangerous methods are allowed: {allow}",
                        evidence=f"Allow: {allow}",
                        cwe="CWE-650",
                        request=req,
                        response=resp,
                    ), callback)

            elif method in ("PUT", "DELETE", "PATCH"):
                # If a restricted endpoint returns 200 with an alternate method
                # when GET returns 403/401, that's an access control bypass
                if get_status in (401, 403, 405) and resp.status_code == 200:
                    self._add_finding(Finding(
                        title=f"Access Control Bypass via {method}",
                        severity=Severity.HIGH,
                        url=url,
                        detail=f"GET returns {get_status} but {method} returns {resp.status_code}, suggesting method-based access control bypass.",
                        evidence=f"GET={get_status}, {method}={resp.status_code}",
                        cwe="CWE-285",
                        request=req,
                        response=resp,
                    ), callback)

    # ------------------------------------------------------------------
    # Passive + Finding management
    # ------------------------------------------------------------------

    def _run_passive(
        self,
        req: HttpRequest,
        resp: HttpResponse,
        callback: Optional[Callable] = None,
    ) -> None:
        """Run passive scanner on every response."""
        findings = self.passive.scan(req, resp)
        for f in findings:
            self._add_finding(f, callback)

    def _add_finding(
        self, finding: Finding, callback: Optional[Callable] = None
    ) -> None:
        # Deduplicate: same title on the same URL path = one finding
        parsed = urlparse(finding.url)
        dedup_key = (finding.title, parsed.path)
        if dedup_key in self._seen_findings:
            return
        self._seen_findings.add(dedup_key)

        self._findings.append(finding)
        self.db.save_finding(finding)
        if callback:
            callback(finding)

    def stop(self) -> None:
        self._running = False
