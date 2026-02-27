"""Plugin: Host header injection testing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import ScanPlugin

if TYPE_CHECKING:
    from ..core.engine import HttpEngine
    from ..core.models import Finding, HttpRequest, HttpResponse


class HostHeaderInjectionPlugin(ScanPlugin):
    name = "host_header_injection"
    description = "Test for host header injection attacks (password reset poisoning, cache poisoning)"
    author = "SnailSploit"

    CANARY = "evil.snailsploit.test"

    async def active_check(
        self, req: "HttpRequest", engine: "HttpEngine"
    ) -> list["Finding"]:
        from ..core.models import Finding, HttpRequest as HttpReq, Severity

        findings = []
        original_host = req.headers.get("Host", req.host)

        # Test 1: X-Forwarded-Host injection
        test_req = HttpReq(
            method=req.method,
            url=req.url,
            headers={**req.headers, "X-Forwarded-Host": self.CANARY},
        )
        resp = await engine.send(test_req)
        body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
        if self.CANARY in body:
            findings.append(
                Finding(
                    title="Host Header Injection via X-Forwarded-Host",
                    severity=Severity.HIGH,
                    url=req.url,
                    detail="Injected X-Forwarded-Host value reflected in response body.",
                    evidence=f"X-Forwarded-Host: {self.CANARY} reflected in response",
                    cwe="CWE-644",
                    request=test_req,
                    response=resp,
                )
            )

        # Test 2: Host header override
        test_req2 = HttpReq(
            method=req.method,
            url=req.url,
            headers={**req.headers, "Host": self.CANARY},
        )
        resp2 = await engine.send(test_req2)
        body2 = resp2.body.decode("utf-8", errors="replace") if resp2.body else ""
        if self.CANARY in body2 and resp2.status_code < 400:
            findings.append(
                Finding(
                    title="Host Header Injection",
                    severity=Severity.HIGH,
                    url=req.url,
                    detail="Modified Host header value reflected in response.",
                    evidence=f"Host: {self.CANARY} reflected in response",
                    cwe="CWE-644",
                    request=test_req2,
                    response=resp2,
                )
            )

        # Test 3: Double Host header (X-Host)
        for header_name in ["X-Host", "X-Original-URL", "X-Rewrite-URL"]:
            test_req3 = HttpReq(
                method=req.method,
                url=req.url,
                headers={**req.headers, header_name: self.CANARY},
            )
            resp3 = await engine.send(test_req3)
            body3 = resp3.body.decode("utf-8", errors="replace") if resp3.body else ""
            if self.CANARY in body3:
                findings.append(
                    Finding(
                        title=f"Host Injection via {header_name}",
                        severity=Severity.MEDIUM,
                        url=req.url,
                        detail=f"Injected {header_name} value reflected in response.",
                        evidence=f"{header_name}: {self.CANARY}",
                        cwe="CWE-644",
                        request=test_req3,
                        response=resp3,
                    )
                )

        return findings
