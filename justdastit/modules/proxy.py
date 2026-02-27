"""justdastit - Intercepting proxy (mitmproxy-based) with cookie bridge."""

from __future__ import annotations

import asyncio
import threading
from typing import Callable, Optional

from ..core.database import ProjectDB
from ..core.models import HttpRequest, HttpResponse, ProjectConfig, ScopeRule
from ..core.session import SessionManager


class ProxyAddon:
    """mitmproxy addon that captures traffic and bridges cookies to SessionManager."""

    def __init__(
        self,
        db: ProjectDB,
        scope: ScopeRule,
        session: Optional[SessionManager] = None,
        intercept_callback: Optional[Callable] = None,
    ) -> None:
        self.db = db
        self.scope = scope
        self.session = session
        self._intercept_callback = intercept_callback
        self.request_count = 0
        self.paused = False

    def set_intercept(self, callback: Callable) -> None:
        """Set a callback for intercepting/modifying traffic."""
        self._intercept_callback = callback

    def clear_intercept(self) -> None:
        """Remove the intercept callback."""
        self._intercept_callback = None

    def request(self, flow) -> None:  # type: ignore
        """Called on each proxied request."""
        if self.paused:
            return
        url = flow.request.pretty_url
        if not self.scope.in_scope(url):
            return

        # Allow intercept callback to modify the request
        if self._intercept_callback:
            self._intercept_callback(flow)

        req = HttpRequest(
            method=flow.request.method,
            url=url,
            headers=dict(flow.request.headers),
            body=flow.request.content,
        )
        flow.metadata["justdastit_req"] = req
        self.request_count += 1

    def response(self, flow) -> None:  # type: ignore
        """Called on each proxied response."""
        if self.paused:
            return
        req = flow.metadata.get("justdastit_req")
        if not req:
            return

        resp = HttpResponse(
            status_code=flow.response.status_code,
            headers=dict(flow.response.headers),
            body=flow.response.content,
        )

        # Save to DB
        self.db.save_request_response(req, resp, tags=["proxy"])
        self.db.add_sitemap_url(
            url=req.url,
            status_code=resp.status_code,
            content_type=resp.content_type,
        )

        # Bridge cookies to SessionManager
        if self.session:
            for key, value in flow.response.headers.get_all("set-cookie"):
                parts = value.split(";")[0]
                if "=" in parts:
                    name, val = parts.split("=", 1)
                    self.session.cookie_jar.set(name.strip(), val.strip())


def start_proxy(
    config: ProjectConfig,
    db: ProjectDB,
    session: Optional[SessionManager] = None,
    intercept_callback: Optional[Callable] = None,
    background: bool = True,
) -> Optional[threading.Thread]:
    """Start the intercepting proxy.

    Requires mitmproxy to be installed: pip install mitmproxy
    """
    try:
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster
    except ImportError:
        print(
            "[!] mitmproxy not installed. Install with: pip install mitmproxy"
        )
        print("[*] Proxy module disabled. Other modules still functional.")
        return None

    addon = ProxyAddon(
        db=db,
        scope=config.scope,
        session=session,
        intercept_callback=intercept_callback,
    )

    def _run() -> None:
        opts = options.Options(
            listen_host=config.proxy_host,
            listen_port=config.proxy_port,
            ssl_insecure=not config.verify_ssl,
        )
        m = DumpMaster(opts)
        m.addons.add(addon)
        print(f"[*] Proxy listening on {config.proxy_host}:{config.proxy_port}")
        try:
            asyncio.run(m.run())
        except KeyboardInterrupt:
            m.shutdown()

    if background:
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        return t
    else:
        _run()
        return None


def generate_ca_cert(output_dir: str = ".") -> str:
    """Generate a CA certificate for SSL interception."""
    try:
        from mitmproxy.certs import CertStore

        certstore = CertStore.from_store(output_dir, "justdastit")
        print(f"[*] CA cert generated in {output_dir}")
        print(f"[*] Install justdastit-ca-cert.pem in your browser")
        return output_dir
    except ImportError:
        print("[!] mitmproxy required for CA cert generation")
        return ""
