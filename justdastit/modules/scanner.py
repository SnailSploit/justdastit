"""justdastit - Passive and active scanner for security analysis."""

from __future__ import annotations

import json
import re
from typing import Optional

from ..core.database import ProjectDB
from ..core.models import (
    Finding,
    HttpRequest,
    HttpResponse,
    RequestResponse,
    Severity,
)


class PassiveScanner:
    """Analyzes HTTP traffic for security issues without sending additional requests."""

    def __init__(self, db: ProjectDB) -> None:
        self.db = db
        self.checks = [
            self._check_security_headers,
            self._check_information_disclosure,
            self._check_sensitive_data,
            self._check_cors,
            self._check_cookie_flags,
            self._check_content_type,
            self._check_server_banner,
            self._check_debug_endpoints,
            self._check_jwt_issues,
            self._check_error_messages,
        ]

    def scan(self, req: HttpRequest, resp: HttpResponse) -> list[Finding]:
        """Run all passive checks on a request/response pair."""
        findings: list[Finding] = []
        for check in self.checks:
            result = check(req, resp)
            if result:
                findings.extend(result)
        return findings

    def scan_all_history(self) -> list[Finding]:
        """Scan all requests in the database."""
        all_findings: list[Finding] = []
        rows = self.db.get_requests(limit=10000)
        for row in rows:
            rr = self.db.get_request_response(row["id"])
            if rr and rr.response:
                findings = self.scan(rr.request, rr.response)
                for f in findings:
                    self.db.save_finding(f, request_id=row["id"])
                all_findings.extend(findings)
        return all_findings

    def _check_security_headers(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        missing_headers = {
            "strict-transport-security": (
                "Missing HSTS Header",
                Severity.MEDIUM,
                "CWE-319",
            ),
            "x-content-type-options": (
                "Missing X-Content-Type-Options",
                Severity.LOW,
                "CWE-693",
            ),
            "x-frame-options": (
                "Missing X-Frame-Options (Clickjacking)",
                Severity.MEDIUM,
                "CWE-1021",
            ),
            "content-security-policy": (
                "Missing Content-Security-Policy",
                Severity.MEDIUM,
                "CWE-693",
            ),
            "x-xss-protection": (
                "Missing X-XSS-Protection",
                Severity.LOW,
                "CWE-79",
            ),
            "referrer-policy": (
                "Missing Referrer-Policy",
                Severity.LOW,
                "CWE-200",
            ),
            "permissions-policy": (
                "Missing Permissions-Policy",
                Severity.INFO,
                None,
            ),
        }

        # Only check HTML responses
        if "html" not in resp.content_type.lower():
            return findings

        for header, (title, severity, cwe) in missing_headers.items():
            if header not in headers:
                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        url=req.url,
                        detail=f"The response is missing the {header} header.",
                        cwe=cwe,
                        request=req,
                        response=resp,
                    )
                )
        return findings

    def _check_information_disclosure(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        body = resp.body.decode("utf-8", errors="replace") if resp.body else ""

        patterns = {
            r"(?i)(sql\s*(?:syntax|error|exception)|mysql_|pg_query|ORA-\d{5}|SQLSTATE)": (
                "SQL Error Information Disclosure",
                Severity.HIGH,
                "CWE-209",
            ),
            r"(?i)(stack\s*trace|traceback|at\s+[\w.]+\([\w.]+:\d+\))": (
                "Stack Trace Disclosure",
                Severity.MEDIUM,
                "CWE-209",
            ),
            r"(?i)(\/(?:home|var|usr|etc|opt)\/[\w\/.-]+\.(?:py|rb|php|java|js))": (
                "Internal Path Disclosure",
                Severity.LOW,
                "CWE-200",
            ),
            r"(?:^|[^.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[^.\d]|$)": (
                "Internal IP Address Disclosure",
                Severity.LOW,
                "CWE-200",
            ),
        }

        for pattern, (title, severity, cwe) in patterns.items():
            matches = re.findall(pattern, body[:50000])  # Limit search
            if matches:
                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        url=req.url,
                        detail=f"Found {len(matches)} match(es) in response body.",
                        evidence=str(matches[:3]),
                        cwe=cwe,
                        request=req,
                        response=resp,
                    )
                )
        return findings

    def _check_sensitive_data(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        body = resp.body.decode("utf-8", errors="replace") if resp.body else ""

        sensitive_patterns = {
            r"(?i)['\"]?(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?[\w-]{20,}": (
                "API Key Exposure",
                Severity.HIGH,
            ),
            r"(?i)['\"]?(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*['\"]?[^\s'\"]{4,}": (
                "Potential Password Exposure",
                Severity.HIGH,
            ),
            r"(?i)(?:aws_?(?:access_?key_?id|secret_?access_?key)|AKIA[0-9A-Z]{16})": (
                "AWS Credential Exposure",
                Severity.CRITICAL,
            ),
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+": (
                "JWT Token in Response",
                Severity.MEDIUM,
            ),
            r"(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}": (
                "GitHub Token Exposure",
                Severity.CRITICAL,
            ),
        }

        for pattern, (title, severity) in sensitive_patterns.items():
            matches = re.findall(pattern, body[:100000])
            if matches:
                findings.append(
                    Finding(
                        title=title,
                        severity=severity,
                        url=req.url,
                        detail=f"Potentially sensitive data found in response.",
                        evidence=str(matches[:2])[:200],
                        cwe="CWE-200",
                        request=req,
                        response=resp,
                    )
                )
        return findings

    def _check_cors(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        acao = headers.get("access-control-allow-origin", "")

        if acao == "*":
            acac = headers.get("access-control-allow-credentials", "").lower()
            if acac == "true":
                findings.append(
                    Finding(
                        title="CORS Misconfiguration: Wildcard with Credentials",
                        severity=Severity.HIGH,
                        url=req.url,
                        detail="The server allows any origin with credentials.",
                        cwe="CWE-942",
                        request=req,
                        response=resp,
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="CORS: Wildcard Origin Allowed",
                        severity=Severity.LOW,
                        url=req.url,
                        detail="Access-Control-Allow-Origin is set to *.",
                        cwe="CWE-942",
                        request=req,
                        response=resp,
                    )
                )
        elif acao and acao != "null":
            # Check if it reflects the Origin header
            origin = req.headers.get("Origin", "")
            if origin and acao == origin:
                findings.append(
                    Finding(
                        title="CORS: Origin Reflection",
                        severity=Severity.MEDIUM,
                        url=req.url,
                        detail="The server reflects the Origin header in ACAO.",
                        evidence=f"Origin: {origin} -> ACAO: {acao}",
                        cwe="CWE-942",
                        request=req,
                        response=resp,
                    )
                )
        return findings

    def _check_cookie_flags(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        set_cookies = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)

        for cookie in set_cookies:
            parts = cookie.lower()
            cookie_name = cookie.split("=")[0].strip()

            if "secure" not in parts:
                findings.append(
                    Finding(
                        title=f"Cookie Missing Secure Flag: {cookie_name}",
                        severity=Severity.MEDIUM,
                        url=req.url,
                        detail=f"Cookie '{cookie_name}' does not have the Secure flag.",
                        cwe="CWE-614",
                        request=req,
                        response=resp,
                    )
                )
            if "httponly" not in parts:
                findings.append(
                    Finding(
                        title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        severity=Severity.MEDIUM,
                        url=req.url,
                        detail=f"Cookie '{cookie_name}' does not have the HttpOnly flag.",
                        cwe="CWE-1004",
                        request=req,
                        response=resp,
                    )
                )
            if "samesite" not in parts:
                findings.append(
                    Finding(
                        title=f"Cookie Missing SameSite: {cookie_name}",
                        severity=Severity.LOW,
                        url=req.url,
                        detail=f"Cookie '{cookie_name}' missing SameSite attribute.",
                        cwe="CWE-1275",
                        request=req,
                        response=resp,
                    )
                )
        return findings

    def _check_content_type(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        ct = resp.content_type.lower()
        body = resp.body.decode("utf-8", errors="replace")[:500] if resp.body else ""

        # JSON with wrong content type
        if body.strip().startswith(("{", "[")) and "json" not in ct and "html" not in ct:
            findings.append(
                Finding(
                    title="JSON Response with Incorrect Content-Type",
                    severity=Severity.LOW,
                    url=req.url,
                    detail=f"Response appears to be JSON but Content-Type is: {ct}",
                    cwe="CWE-436",
                    request=req,
                    response=resp,
                )
            )
        return findings

    def _check_server_banner(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")

        if server and re.search(r"\d+\.\d+", server):
            findings.append(
                Finding(
                    title="Server Version Disclosure",
                    severity=Severity.LOW,
                    url=req.url,
                    detail=f"Server header reveals version: {server}",
                    evidence=server,
                    cwe="CWE-200",
                    request=req,
                    response=resp,
                )
            )
        if powered_by:
            findings.append(
                Finding(
                    title="Technology Stack Disclosure",
                    severity=Severity.LOW,
                    url=req.url,
                    detail=f"X-Powered-By header reveals: {powered_by}",
                    evidence=powered_by,
                    cwe="CWE-200",
                    request=req,
                    response=resp,
                )
            )
        return findings

    def _check_debug_endpoints(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        debug_paths = [
            "/debug", "/trace", "/_debug", "/console", "/phpinfo",
            "/server-status", "/server-info", "/.env", "/wp-config",
            "/elmah.axd", "/actuator", "/swagger", "/api-docs",
        ]
        path = req.path.lower()
        if any(dp in path for dp in debug_paths) and resp.status_code == 200:
            findings.append(
                Finding(
                    title="Debug/Admin Endpoint Accessible",
                    severity=Severity.HIGH,
                    url=req.url,
                    detail=f"Debug or admin endpoint is accessible: {req.path}",
                    cwe="CWE-215",
                    request=req,
                    response=resp,
                )
            )
        return findings

    def _check_jwt_issues(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        import base64

        # Check Authorization header
        auth = req.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    header = json.loads(
                        base64.urlsafe_b64decode(parts[0] + "==")
                    )
                    if header.get("alg") == "none":
                        findings.append(
                            Finding(
                                title="JWT with 'none' Algorithm",
                                severity=Severity.CRITICAL,
                                url=req.url,
                                detail="JWT uses 'none' algorithm - no signature verification.",
                                cwe="CWE-347",
                                request=req,
                                response=resp,
                            )
                        )
                    elif header.get("alg") in ("HS256", "HS384", "HS512"):
                        findings.append(
                            Finding(
                                title="JWT Uses Symmetric Algorithm",
                                severity=Severity.INFO,
                                url=req.url,
                                detail=f"JWT uses symmetric algorithm: {header['alg']}. Test for key confusion.",
                                cwe="CWE-327",
                                request=req,
                                response=resp,
                            )
                        )
                except Exception:
                    pass
        return findings

    def _check_error_messages(
        self, req: HttpRequest, resp: HttpResponse
    ) -> list[Finding]:
        findings = []
        if resp.status_code >= 500 and resp.body:
            body = resp.body.decode("utf-8", errors="replace")
            verbose_patterns = [
                r"(?i)exception in thread",
                r"(?i)fatal error",
                r"(?i)unhandled exception",
                r"(?i)debug mode",
                r"(?i)development server",
            ]
            for pattern in verbose_patterns:
                if re.search(pattern, body):
                    findings.append(
                        Finding(
                            title="Verbose Error Message",
                            severity=Severity.MEDIUM,
                            url=req.url,
                            detail=f"Server error response contains verbose debugging information.",
                            cwe="CWE-209",
                            request=req,
                            response=resp,
                        )
                    )
                    break
        return findings
