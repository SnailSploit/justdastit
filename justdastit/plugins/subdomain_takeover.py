"""Plugin: Subdomain takeover detection via CNAME checking."""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .base import ScanPlugin

if TYPE_CHECKING:
    from ..core.engine import HttpEngine
    from ..core.models import Finding, HttpRequest, HttpResponse

# Known fingerprints for dangling CNAME targets
TAKEOVER_FINGERPRINTS = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "no such app",
    "pantheonsite.io": "404 error unknown site",
    "domains.tumblr.com": "Whatever you were looking for doesn't currently exist",
    "wordpress.com": "Do you want to register",
    "teamwork.com": "Oops - We didn't find your site",
    "helpjuice.com": "We could not find what you're looking for",
    "helpscoutdocs.com": "No settings were found for this company",
    "ghost.io": "The thing you were looking for is no longer here",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "s3.amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "ERROR: The request could not be satisfied",
    "azurewebsites.net": "404 Web Site not found",
    "cloudapp.net": "not found",
    "trafficmanager.net": "not found",
    "blob.core.windows.net": "BlobNotFound",
    "unbouncepages.com": "The requested URL was not found",
    "landingi.com": "It looks like you",
    "ngrok.io": "Tunnel not found",
    "cargocollective.com": "404 Not Found",
    "feedpress.me": "The feed has not been found",
    "statuspage.io": "You are being redirected",
    "zendesk.com": "Help Center Closed",
    "readme.io": "Project doesnt exist",
    "fly.dev": "404 Not Found",
}


class SubdomainTakeoverPlugin(ScanPlugin):
    name = "subdomain_takeover"
    description = "Check for dangling CNAME records that could allow subdomain takeover"
    author = "SnailSploit"

    def passive_check(
        self, req: "HttpRequest", resp: "HttpResponse"
    ) -> list["Finding"]:
        from ..core.models import Finding, Severity

        findings = []
        body = resp.body.decode("utf-8", errors="replace") if resp.body else ""

        for cname_target, fingerprint in TAKEOVER_FINGERPRINTS.items():
            if fingerprint.lower() in body.lower():
                findings.append(
                    Finding(
                        title=f"Potential Subdomain Takeover ({cname_target})",
                        severity=Severity.HIGH,
                        url=req.url,
                        detail=f"Response contains fingerprint for unclaimed {cname_target} resource.",
                        evidence=fingerprint,
                        cwe="CWE-284",
                        request=req,
                        response=resp,
                        remediation=f"Check if CNAME points to {cname_target} and claim the resource or remove the DNS record.",
                    )
                )
        return findings

    async def active_check(
        self, req: "HttpRequest", engine: "HttpEngine"
    ) -> list["Finding"]:
        from ..core.models import Finding, Severity

        findings = []
        hostname = urlparse(req.url).hostname or ""

        try:
            cname = socket.getfqdn(hostname)
            for target in TAKEOVER_FINGERPRINTS:
                if target in cname and cname != hostname:
                    resp = await engine.send(req)
                    body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
                    fingerprint = TAKEOVER_FINGERPRINTS[target]
                    if fingerprint.lower() in body.lower():
                        findings.append(
                            Finding(
                                title=f"Subdomain Takeover: {hostname} -> {cname}",
                                severity=Severity.HIGH,
                                url=req.url,
                                detail=f"CNAME {hostname} -> {cname} points to unclaimed resource.",
                                evidence=f"CNAME: {cname}, Fingerprint: {fingerprint}",
                                cwe="CWE-284",
                                request=req,
                                response=resp,
                            )
                        )
        except (socket.gaierror, OSError):
            pass

        return findings
