"""Plugin: Open Redirect detection via parameter injection."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import ScanPlugin

if TYPE_CHECKING:
    from ..core.engine import HttpEngine
    from ..core.models import Finding, HttpRequest, HttpResponse


class OpenRedirectPlugin(ScanPlugin):
    name = "open_redirect"
    description = "Detect open redirect vulnerabilities via parameter injection"
    author = "SnailSploit"

    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
        "returnTo", "next", "goto", "target", "dest", "destination", "redir",
        "continue", "forward", "out", "view", "ref", "callback", "path",
    ]

    CANARY_DOMAIN = "https://evil.snailsploit.test"

    def passive_check(
        self, req: "HttpRequest", resp: "HttpResponse"
    ) -> list["Finding"]:
        from ..core.models import Finding, Severity

        findings = []
        parsed = urlparse(req.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if param_name.lower() in [p.lower() for p in self.REDIRECT_PARAMS]:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if location and not location.startswith("/"):
                        findings.append(
                            Finding(
                                title=f"Potential Open Redirect via '{param_name}'",
                                severity=Severity.MEDIUM,
                                url=req.url,
                                detail=f"Redirect parameter '{param_name}' leads to external redirect.",
                                evidence=f"Location: {location}",
                                cwe="CWE-601",
                                request=req,
                                response=resp,
                            )
                        )
        return findings

    async def active_check(
        self, req: "HttpRequest", engine: "HttpEngine"
    ) -> list["Finding"]:
        from ..core.models import Finding, HttpRequest as HttpReq, Severity

        findings = []
        parsed = urlparse(req.url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if param_name.lower() in [p.lower() for p in self.REDIRECT_PARAMS]:
                test_params = dict(params)
                test_params[param_name] = [self.CANARY_DOMAIN]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                test_req = HttpReq(
                    method=req.method,
                    url=test_url,
                    headers=dict(req.headers),
                )
                resp = await engine.send(test_req)

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if self.CANARY_DOMAIN in location:
                        findings.append(
                            Finding(
                                title=f"Open Redirect via '{param_name}'",
                                severity=Severity.MEDIUM,
                                url=req.url,
                                detail=f"Injecting canary domain into '{param_name}' causes redirect to attacker-controlled domain.",
                                evidence=f"Location: {location}",
                                cwe="CWE-601",
                                request=test_req,
                                response=resp,
                            )
                        )
        return findings
