"""justdastit - CLI entry point. Click + Rich powered."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

from .core.database import ProjectDB
from .core.engine import HttpEngine
from .core.models import HttpRequest, ProjectConfig, ScopeRule, Severity
from .core.session import LoginConfig, SessionManager
from .modules.intruder import BUILTIN_PAYLOADS, AttackType, Intruder, IntruderConfig, IntruderResult
from .modules.repeater import Repeater
from .modules.scanner import PassiveScanner
from .utils.decoder import DECODERS, ENCODERS, HASHERS, smart_decode

console = Console()

BANNER = r"""[cyan]
     ██╗██╗   ██╗███████╗████████╗██████╗  █████╗ ███████╗████████╗██╗████████╗
     ██║██║   ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║╚══██╔══╝
     ██║██║   ██║███████╗   ██║   ██║  ██║███████║███████╗   ██║   ██║   ██║
██   ██║██║   ██║╚════██║   ██║   ██║  ██║██╔══██║╚════██║   ██║   ██║   ██║
╚█████╔╝╚██████╔╝███████║   ██║   ██████╔╝██║  ██║███████║   ██║   ██║   ██║
 ╚════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝   ╚═╝[/cyan]
[dim]                    The Burp You Can Afford™  v3.0.0
                    github.com/snailsploit/justdastit[/dim]
"""

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def status_style(code: int) -> str:
    if code < 300:
        return "green"
    elif code < 400:
        return "cyan"
    elif code < 500:
        return "yellow"
    return "red"


def _load_config(ctx: click.Context) -> tuple[ProjectConfig, ProjectDB]:
    """Load config from context, merging CLI overrides."""
    db_path = ctx.obj.get("db", "justdastit.db")
    timeout = ctx.obj.get("timeout", 10.0)
    ua = ctx.obj.get("ua", "justdastit/3.0")

    # Try loading YAML config
    config = ProjectConfig(db_path=db_path, timeout=timeout, user_agent=ua)
    try:
        from .utils.config import load_config

        config = load_config(
            config_path=ctx.obj.get("config"),
            cli_overrides={"db_path": db_path, "timeout": timeout, "user_agent": ua},
        )
    except ImportError:
        pass

    # Apply auth from CLI
    auth = ctx.obj.get("auth")
    if auth:
        parts = auth.split(" ", 1)
        if len(parts) == 2:
            config.auth_type = parts[0].lower()
            config.auth_value = parts[1]

    db = ProjectDB(config.db_path)
    return config, db


def _setup_engine(config: ProjectConfig, session: Optional[SessionManager] = None) -> HttpEngine:
    """Create an HttpEngine with auth configured."""
    session = session or SessionManager(config)
    engine = HttpEngine(config, session=session)
    if config.auth_type and config.auth_value:
        if config.auth_type == "bearer":
            engine.set_auth_bearer(config.auth_value)
        elif config.auth_type == "basic":
            parts = config.auth_value.split(":", 1)
            if len(parts) == 2:
                engine.set_auth_basic(parts[0], parts[1])
        elif config.auth_type == "header":
            parts = config.auth_value.split(":", 1)
            if len(parts) == 2:
                engine.set_auth_header(parts[0].strip(), parts[1].strip())
    if config.delay_ms > 0:
        engine.set_rate_limit(config.delay_ms)
    return engine


# ── Main Group ────────────────────────────────────────────────────────


@click.group(invoke_without_command=True)
@click.option("--db", default="justdastit.db", help="Project database file path.")
@click.option("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds.")
@click.option("--ua", default="justdastit/3.0", help="User-Agent string.")
@click.option("--config", type=click.Path(exists=True), default=None, help="Path to justdastit.yaml config file.")
@click.option("--auth", default=None, help='Auth: "bearer TOKEN", "basic USER:PASS", or "header Name:Value".')
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output.")
@click.pass_context
def cli(ctx: click.Context, db: str, timeout: float, ua: str, config: Optional[str], auth: Optional[str], verbose: bool) -> None:
    """justdastit — The Burp You Can Afford.

    Open-source DAST toolkit for web security testing.
    Spider, fuzz, scan, repeat, decode — all from your terminal.

    \b
    Quick start:
      justdastit spider https://target.com
      justdastit fuzz "https://target.com/search?q=test"
      justdastit scan
      justdastit findings
    """
    ctx.ensure_object(dict)
    ctx.obj["db"] = db
    ctx.obj["timeout"] = timeout
    ctx.obj["ua"] = ua
    ctx.obj["config"] = config
    ctx.obj["auth"] = auth
    ctx.obj["verbose"] = verbose

    if ctx.invoked_subcommand is None:
        console.print(BANNER)
        console.print(ctx.get_help())


# ── Init ──────────────────────────────────────────────────────────────


@cli.command()
@click.option("--output", "-o", default="justdastit.yaml", help="Output file path.")
def init(output: str) -> None:
    """Generate a starter justdastit.yaml config file.

    \b
    Examples:
      justdastit init
      justdastit init -o myproject.yaml
    """
    try:
        from .utils.config import generate_default_config

        path = generate_default_config(output)
        console.print(f"[green]Config file created:[/green] {path}")
        console.print("[dim]Edit scope, auth, and scanner settings, then run your scan.[/dim]")
    except ImportError:
        console.print("[red]pyyaml required.[/red] Install with: pip install justdastit[config]")


# ── Proxy ─────────────────────────────────────────────────────────────


@cli.command()
@click.option("--port", type=int, default=8080, help="Proxy listen port.")
@click.option("--scope", default=None, help="Scope domain pattern.")
@click.pass_context
def proxy(ctx: click.Context, port: int, scope: Optional[str]) -> None:
    """Start the intercepting proxy (requires mitmproxy).

    \b
    Examples:
      justdastit proxy
      justdastit proxy --port 9090 --scope "*.target.com"
    """
    config, db = _load_config(ctx)
    config.proxy_port = port
    if scope:
        config.scope = ScopeRule(include_patterns=[scope])

    console.print(f"[green]Starting proxy on {config.proxy_host}:{config.proxy_port}[/green]")
    if scope:
        console.print(f"[cyan]Scope: {scope}[/cyan]")
    console.print("[yellow]Configure browser proxy and install CA cert[/yellow]")
    console.print("[dim]Ctrl+C to stop[/dim]\n")

    try:
        from .modules.proxy import start_proxy

        start_proxy(config, db, background=False)
    except ImportError:
        console.print("[red]mitmproxy not installed.[/red] Install with: pip install justdastit[proxy]")


# ── Spider ────────────────────────────────────────────────────────────


@cli.command()
@click.argument("url")
@click.option("--depth", "-d", type=int, default=3, help="Max crawl depth.")
@click.option("--threads", "-t", type=int, default=10, help="Concurrent requests.")
@click.option("--scope", default=None, help="Scope domain pattern (auto-detected from URL if not set).")
@click.pass_context
def spider(ctx: click.Context, url: str, depth: int, threads: int, scope: Optional[str]) -> None:
    """Crawl a target URL and discover pages, forms, and endpoints.

    \b
    Examples:
      justdastit spider https://target.com
      justdastit spider https://target.com --depth 5 --threads 20
      justdastit spider https://target.com --scope "*.target.com"
    """
    config, db = _load_config(ctx)

    if scope:
        config.scope = ScopeRule(include_patterns=[scope])
    else:
        host = urlparse(url).hostname or ""
        config.scope = ScopeRule(include_patterns=[host])

    engine = _setup_engine(config)
    from .modules.spider import Spider

    sp = Spider(engine, db, config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed} URLs[/cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Spidering {url}", total=None)

        async def on_url(discovered_url: str, resp: object, d: int) -> None:
            progress.update(task, advance=1, description=f"[d={d}] {discovered_url[:80]}")

        async def run() -> None:
            stats = await sp.crawl(
                start_urls=[url],
                max_depth=depth,
                concurrency=threads,
                callback=on_url,
            )
            await engine.close()

        asyncio.run(run())

    stats = sp.stats
    console.print(f"\n[green]Spider complete[/green]")

    table = Table(title="Spider Results", show_header=False, border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("URLs Visited", str(stats["visited"]))
    table.add_row("Links Found", str(stats["links_found"]))
    table.add_row("Forms Discovered", str(stats["forms"]))
    console.print(table)

    if sp.forms_found:
        form_table = Table(title="Discovered Forms", border_style="dim")
        form_table.add_column("Method", style="yellow")
        form_table.add_column("Action", style="white")
        form_table.add_column("Inputs", style="dim")
        for form in sp.forms_found[:20]:
            inputs = ", ".join(f"{i['name']}({i['type']})" for i in form["inputs"] if i["name"])
            form_table.add_row(form["method"], form["action"][:80], inputs[:60])
            # Save to DB
            db.save_form(
                url=form.get("found_on", url),
                action=form["action"],
                method=form["method"],
                inputs=form["inputs"],
                found_on=form.get("found_on", url),
            )
        console.print(form_table)


# ── Fuzz ──────────────────────────────────────────────────────────────


@cli.command()
@click.argument("url")
@click.option("-p", "--payloads", default="xss", help=f"Payload file or type ({', '.join(BUILTIN_PAYLOADS.keys())}).")
@click.option("-a", "--attack", default="sniper", type=click.Choice(["sniper", "battering_ram", "pitchfork", "cluster_bomb"]), help="Attack mode.")
@click.option("-t", "--threads", type=int, default=10, help="Concurrent requests.")
@click.option("-X", "--method", default="GET", help="HTTP method.")
@click.option("-d", "--data", default=None, help="POST body data.")
@click.option("-H", "--header", "headers", multiple=True, help="Custom header (Key: Value). Repeatable.")
@click.option("-b", "--cookie", default=None, help="Cookie header value.")
@click.option("--delay", type=float, default=0, help="Delay between requests (ms).")
@click.option("--match-regex", default=None, help="Highlight responses matching this regex.")
@click.option("--grep", multiple=True, help="Extract regex matches from responses. Repeatable.")
@click.pass_context
def fuzz(ctx: click.Context, url: str, payloads: str, attack: str, threads: int,
         method: str, data: Optional[str], headers: tuple, cookie: Optional[str],
         delay: float, match_regex: Optional[str], grep: tuple) -> None:
    """Fuzz URL parameters with payloads (Intruder).

    Auto-detects injection points from URL params, POST body, JSON, and cookies.
    Smart defaults: run with just a URL and it picks sniper mode + XSS payloads.

    \b
    Examples:
      justdastit fuzz "https://target.com/search?q=test"
      justdastit fuzz "https://target.com/search?q=test" -p sqli -t 20
      justdastit fuzz "https://target.com/login" -d "user=admin&pass=test" -p sqli
      justdastit fuzz "https://target.com/api" -X POST -d '{"q":"test"}' -p xss
      justdastit fuzz "https://target.com/page?id=1" -p lfi --grep "root:"
      justdastit fuzz "https://target.com/search?q=test" -a battering_ram -p cmdi
    """
    config, db = _load_config(ctx)
    engine = _setup_engine(config)
    intruder = Intruder(engine, db)

    base_req = HttpRequest(
        method=method,
        url=url,
        headers={"User-Agent": config.user_agent},
    )
    if data:
        base_req.body = data.encode()
        if method == "GET" and "-X" not in sys.argv:
            base_req.method = "POST"
    for h in headers:
        key, val = h.split(":", 1)
        base_req.headers[key.strip()] = val.strip()
    if cookie:
        base_req.headers["Cookie"] = cookie

    positions = Intruder.auto_detect_positions(base_req)
    if not positions:
        console.print("[red]No fuzzable positions detected.[/red] Add parameters to the URL or body.")
        return

    # Load payloads
    if payloads in BUILTIN_PAYLOADS:
        payload_list = BUILTIN_PAYLOADS[payloads]()
    elif Path(payloads).exists():
        payload_list = Intruder.load_payloads(payloads)
    else:
        # Try loading from bundled wordlists
        wordlist_path = Path(__file__).parent / "wordlists" / f"{payloads}.txt"
        if wordlist_path.exists():
            payload_list = Intruder.load_payloads(str(wordlist_path))
        else:
            console.print(f"[red]Unknown payload source: {payloads}[/red]")
            console.print(f"Built-in: {', '.join(BUILTIN_PAYLOADS.keys())}")
            return

    # Display config
    console.print(Panel.fit(
        f"[cyan]Target:[/cyan] {url}\n"
        f"[cyan]Positions:[/cyan] {len(positions)} detected\n"
        f"[cyan]Payloads:[/cyan] {payloads} ({len(payload_list)} payloads)\n"
        f"[cyan]Attack:[/cyan] {attack} | [cyan]Threads:[/cyan] {threads}",
        title="Fuzzer Config",
        border_style="cyan",
    ))

    for i, pos in enumerate(positions):
        console.print(f"  [dim][{i}][/dim] {pos.name} = [yellow]{pos.original_value[:50]}[/yellow]")

    attack_type = AttackType(attack)
    intruder_config = IntruderConfig(
        base_request=base_req,
        positions=positions,
        payloads=[payload_list],
        attack_type=attack_type,
        concurrency=threads,
        delay_ms=delay,
        match_regex=match_regex,
        grep_patterns=list(grep),
    )

    results: list[IntruderResult] = []
    start_time = time.time()
    matched_count = 0

    result_table = Table(border_style="dim", show_header=True, header_style="bold")
    result_table.add_column("", width=3)
    result_table.add_column("Status", width=6)
    result_table.add_column("Length", width=10, justify="right")
    result_table.add_column("Time", width=10, justify="right")
    result_table.add_column("Payload", ratio=1)
    result_table.add_column("Grep", style="magenta", width=30)

    def on_result(result: IntruderResult) -> None:
        nonlocal matched_count
        marker = "[yellow]*[/yellow]" if result.matched else " "
        if result.matched:
            matched_count += 1
        style = status_style(result.response.status_code)
        grep_str = result.grep_matches[0][:30] if result.grep_matches else ""
        result_table.add_row(
            marker,
            f"[{style}]{result.response.status_code}[/{style}]",
            f"{result.response.content_length}B",
            f"{result.response.elapsed_ms:.0f}ms",
            result.payload[:60],
            grep_str,
        )

    async def run() -> None:
        nonlocal results
        results = await intruder.attack(intruder_config, callback=on_result)
        await engine.close()

    with console.status("[cyan]Fuzzing...[/cyan]"):
        asyncio.run(run())

    console.print(result_table)

    elapsed = time.time() - start_time
    console.print(f"\n[green]Fuzzing complete[/green]")
    console.print(
        f"  Requests: {len(results)} | Matched: {matched_count} | "
        f"Time: {elapsed:.1f}s | Rate: {len(results) / max(elapsed, 0.1):.1f} req/s"
    )


# ── Directory Bruteforce ──────────────────────────────────────────────


@cli.command()
@click.argument("url")
@click.option("-w", "--wordlist", default=None, help="Wordlist file (defaults to bundled dirs.txt).")
@click.option("-t", "--threads", type=int, default=20, help="Concurrent requests.")
@click.option("-x", "--extensions", default="", help="Comma-separated extensions to append (e.g. php,html,asp).")
@click.option("--status", "status_codes", default="200,201,204,301,302,307,401,403", help="Comma-separated status codes to show.")
@click.option("--hide-size", type=int, default=None, help="Hide responses of this exact byte size.")
@click.option("--follow", is_flag=True, help="Follow redirects.")
@click.pass_context
def dirbrute(ctx: click.Context, url: str, wordlist: Optional[str], threads: int,
             extensions: str, status_codes: str, hide_size: Optional[int], follow: bool) -> None:
    """Bruteforce directories and files on a target.

    Uses the bundled dirs.txt wordlist by default. Add --extensions to
    also try paths with file extensions appended.

    \b
    Examples:
      justdastit dirbrute https://target.com
      justdastit dirbrute https://target.com -x php,html,txt
      justdastit dirbrute https://target.com -w /path/to/wordlist.txt -t 50
      justdastit dirbrute https://target.com --status 200,403 --hide-size 1234
    """
    config, db = _load_config(ctx)
    engine = _setup_engine(config)

    # Load wordlist
    if wordlist and Path(wordlist).exists():
        words = [l.strip() for l in Path(wordlist).read_text().splitlines() if l.strip() and not l.startswith("#")]
    else:
        bundled = Path(__file__).parent / "wordlists" / "dirs.txt"
        if bundled.exists():
            words = [l.strip() for l in bundled.read_text().splitlines() if l.strip() and not l.startswith("#")]
        else:
            console.print("[red]No wordlist found.[/red] Provide one with -w.")
            return

    # Build path list with extensions
    exts = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()] if extensions else []
    paths: list[str] = []
    for w in words:
        paths.append(w)
        for ext in exts:
            paths.append(f"{w}.{ext}")

    allowed_statuses = set(int(s.strip()) for s in status_codes.split(",") if s.strip())
    base_url = url.rstrip("/")

    console.print(Panel.fit(
        f"[cyan]Target:[/cyan] {base_url}\n"
        f"[cyan]Wordlist:[/cyan] {len(words)} words ({len(paths)} with extensions)\n"
        f"[cyan]Threads:[/cyan] {threads} | [cyan]Extensions:[/cyan] {', '.join(exts) or 'none'}\n"
        f"[cyan]Show status:[/cyan] {status_codes}",
        title="Directory Bruteforce",
        border_style="cyan",
    ))

    result_table = Table(border_style="dim", show_header=True, header_style="bold")
    result_table.add_column("Status", width=7)
    result_table.add_column("Size", width=10, justify="right")
    result_table.add_column("Time", width=8, justify="right")
    result_table.add_column("Path", ratio=1)

    found_count = 0
    total_requests = 0

    async def run() -> None:
        nonlocal found_count, total_requests
        sem = asyncio.Semaphore(threads)

        async def check_path(path: str) -> None:
            nonlocal found_count, total_requests
            test_url = f"{base_url}/{path.lstrip('/')}"
            req = HttpRequest(method="GET", url=test_url, headers={"User-Agent": config.user_agent})
            async with sem:
                resp = await engine.send(req)
                total_requests += 1

            if resp.status_code in allowed_statuses:
                size = resp.content_length
                if hide_size is not None and size == hide_size:
                    return
                found_count += 1
                style = status_style(resp.status_code)
                result_table.add_row(
                    f"[{style}]{resp.status_code}[/{style}]",
                    f"{size}B",
                    f"{resp.elapsed_ms:.0f}ms",
                    f"/{path}",
                )
                # Save to DB
                db.add_sitemap_url(
                    url=test_url,
                    status_code=resp.status_code,
                    content_type=resp.content_type,
                    discovered_from="dirbrute",
                    depth=0,
                )

        tasks = [asyncio.create_task(check_path(p)) for p in paths]
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.close()

    start_time = time.time()
    with console.status(f"[cyan]Bruteforcing {len(paths)} paths...[/cyan]"):
        asyncio.run(run())

    console.print(result_table)
    elapsed = time.time() - start_time
    console.print(f"\n[green]Dirbrute complete[/green]")
    console.print(f"  Found: {found_count} | Requests: {total_requests} | "
                  f"Time: {elapsed:.1f}s | Rate: {total_requests / max(elapsed, 0.1):.0f} req/s")


# ── Repeat ────────────────────────────────────────────────────────────


@cli.command()
@click.argument("request_id", type=int, required=False, default=None)
@click.option("--raw", default=None, help="Raw HTTP request file or string.")
@click.option("-m", "--modify", multiple=True, help="Modify: H:Header=Val or P:param=val.")
@click.option("-v", "--verbose", is_flag=True, help="Show full response headers and body.")
@click.pass_context
def repeat(ctx: click.Context, request_id: Optional[int], raw: Optional[str], modify: tuple, verbose: bool) -> None:
    """Replay a captured request from history (Repeater).

    \b
    Examples:
      justdastit repeat 42
      justdastit repeat 42 -v
      justdastit repeat 42 -m "H:X-Custom=test" -m "P:id=999"
      justdastit repeat --raw request.txt -v
    """
    config, db = _load_config(ctx)
    engine = _setup_engine(config)
    repeater = Repeater(engine, db)

    async def run() -> None:
        if raw:
            raw_data = Path(raw).read_text() if Path(raw).exists() else raw
            req = Repeater.from_raw(raw_data)
        elif request_id is not None:
            rr = db.get_request_response(request_id)
            if not rr:
                console.print(f"[red]Request ID {request_id} not found[/red]")
                return
            req = rr.request
        else:
            console.print("[red]Provide a request ID or --raw[/red]")
            return

        add_headers: dict[str, str] = {}
        params: dict[str, str] = {}
        for m in modify:
            key, val = m.split("=", 1)
            if key.startswith("H:"):
                add_headers[key[2:]] = val
            elif key.startswith("P:"):
                params[key[2:]] = val

        resp = await repeater.send_modified(
            req, add_headers=add_headers or None, params=params or None
        )

        style = status_style(resp.status_code)
        console.print(f"\n[green]{req.method} {req.url}[/green]")
        console.print(f"Status: [{style}]{resp.status_code}[/{style}] | Length: {resp.content_length}B | Time: {resp.elapsed_ms:.1f}ms")

        if verbose or ctx.obj.get("verbose"):
            console.print("\n[dim]Response Headers:[/dim]")
            for k, v in resp.headers.items():
                console.print(f"  [dim]{k}:[/dim] {v}")
            if resp.body:
                console.print("\n[dim]Response Body:[/dim]")
                body_str = resp.body.decode("utf-8", errors="replace")[:5000]
                ct = resp.content_type.lower()
                if "json" in ct:
                    try:
                        console.print(Syntax(json.dumps(json.loads(body_str), indent=2), "json"))
                    except (json.JSONDecodeError, ValueError):
                        console.print(body_str)
                elif "html" in ct:
                    console.print(Syntax(body_str, "html"))
                else:
                    console.print(body_str)

        await engine.close()

    asyncio.run(run())


# ── Scan ──────────────────────────────────────────────────────────────


@cli.command()
@click.option("--active", is_flag=True, help="Run active scanner (sends requests).")
@click.option("--threads", "-t", type=int, default=10, help="Concurrent threads for active scanning.")
@click.pass_context
def scan(ctx: click.Context, active: bool, threads: int) -> None:
    """Run scanner on captured traffic.

    By default runs passive analysis (no extra requests).
    Use --active to auto-attack all discovered injection points.

    \b
    Examples:
      justdastit scan
      justdastit scan --active
      justdastit scan --active --threads 20
    """
    config, db = _load_config(ctx)

    if active:
        engine = _setup_engine(config)
        from .modules.active_scanner import ActiveScanner

        scanner = ActiveScanner(engine, db, config)

        console.print("[cyan]Running active scanner on all discovered endpoints...[/cyan]")

        def on_finding(f: object) -> None:
            finding = f  # type: ignore
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            style = SEVERITY_STYLES.get(sev, "dim")
            console.print(f"  [{style}][{sev.upper()}][/{style}] {finding.title}")

        async def run() -> object:
            result = await scanner.scan(concurrency=threads, callback=on_finding)
            await engine.close()
            return result

        result = asyncio.run(run())
        console.print(f"\n[green]Active scan complete[/green]")
        console.print(f"  Requests: {result.requests_sent} | URLs Tested: {result.urls_tested} | "
                      f"Findings: {len(result.findings)} | Time: {result.elapsed_seconds:.1f}s")

        # DAST Coverage Table
        if result.dast_coverage:
            console.print()
            dast_table = Table(title="DAST Coverage — Active Testing Performed", border_style="cyan")
            dast_table.add_column("Attack Category", style="bold", ratio=2)
            dast_table.add_column("Probes Sent", justify="right", style="cyan")
            dast_table.add_column("Params Tested", justify="right")
            dast_table.add_column("Vulns Found", justify="right")

            for cat, cov in result.dast_coverage.items():
                if cov.probes_sent == 0:
                    continue
                vuln_style = "bold red" if cov.findings_count > 0 else "green"
                vuln_text = f"[{vuln_style}]{cov.findings_count}[/{vuln_style}]"
                dast_table.add_row(cat, str(cov.probes_sent), str(cov.params_tested), vuln_text)

            console.print(dast_table)
    else:
        scanner = PassiveScanner(db)
        console.print("[cyan]Running passive scan on captured traffic...[/cyan]")
        findings = scanner.scan_all_history()

        if findings:
            console.print(f"\n[yellow]Found {len(findings)} issue(s):[/yellow]\n")
            for f in findings:
                sev = f.severity.value
                style = SEVERITY_STYLES.get(sev, "dim")
                console.print(f"  [{style}][{sev.upper()}][/{style}] {f.title}")
                console.print(f"    URL: {f.url}")
                if f.detail:
                    console.print(f"    [dim]{f.detail}[/dim]")
                if f.evidence:
                    console.print(f"    Evidence: {f.evidence[:200]}")
                console.print()
        else:
            console.print("[green]No issues found.[/green]")


# ── Autopilot ────────────────────────────────────────────────────────


@cli.command()
@click.argument("url")
@click.option("--depth", "-d", type=int, default=3, help="Spider max crawl depth.")
@click.option("--threads", "-t", type=int, default=10, help="Concurrent requests per stage.")
@click.option("--wordlist", "-w", default=None, help="Dirbrute wordlist (defaults to bundled dirs.txt).")
@click.option("--extensions", "-x", default="", help="Comma-separated extensions for dirbrute (e.g. php,html).")
@click.option("--report", "-r", default=None, help="Report output path (auto-named if omitted).")
@click.option("--format", "-f", "fmt", default="html", type=click.Choice(["html", "md", "json"]), help="Report format.")
@click.option("--skip-dirbrute", is_flag=True, help="Skip directory bruteforce stage.")
@click.option("--skip-active", is_flag=True, help="Skip active scanning stage.")
@click.option("--scope", default=None, help="Scope domain pattern (auto-detected from URL if not set).")
@click.option("--cookie", "-b", default=None, help="Cookie header (e.g. 'PHPSESSID=abc123; security=low').")
@click.option("--auth-url", default=None, help="Login form URL for auto-authentication.")
@click.option("--auth-data", default=None, help="Login POST data (e.g. 'username=admin&password=password&Login=Login').")
@click.option("--browser", is_flag=True, help="Use headless browser (Playwright) for SPA crawling.")
@click.pass_context
def autopilot(ctx: click.Context, url: str, depth: int, threads: int, wordlist: Optional[str],
              extensions: str, report: Optional[str], fmt: str, skip_dirbrute: bool,
              skip_active: bool, scope: Optional[str], cookie: Optional[str],
              auth_url: Optional[str], auth_data: Optional[str], browser: bool) -> None:
    """Run the full scan pipeline automatically.

    Chains all modules: spider → dirbrute → passive scan → active scan → report.
    Each stage feeds its output into the next via the project database.

    \b
    Examples:
      justdastit autopilot https://target.com
      justdastit autopilot https://target.com -d 5 -t 20
      justdastit autopilot https://target.com --skip-dirbrute --format md
      justdastit autopilot https://target.com -x php,html -r report.html
      justdastit autopilot https://target.com --browser  # SPA crawling
      justdastit autopilot https://target.com --auth-url http://t/login --auth-data "user=admin&pass=admin"
    """
    config, db = _load_config(ctx)

    # Start fresh — stale data from previous runs causes session check failures
    # and pollutes results with outdated sitemap/form entries.
    db.reset()

    # Auto-detect scope from URL
    if scope:
        config.scope = ScopeRule(include_patterns=[scope])
    else:
        host = urlparse(url).hostname or ""
        config.scope = ScopeRule(include_patterns=[host])

    # Create SessionManager and engine
    session = SessionManager(config)
    engine = _setup_engine(config, session=session)

    # Inject session cookies via SessionManager (domain-scoped)
    if cookie:
        domain = urlparse(url).hostname or "localhost"
        cookies_dict = {}
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies_dict[k.strip()] = v.strip()
        session.set_cookies(cookies_dict, domain=domain)
        console.print(f"  [dim]Session cookies loaded: {', '.join(cookies_dict.keys())}[/dim]")

    # Configure auto-authentication via SessionManager
    if auth_url and auth_data:
        auth_fields: dict[str, str] = {}
        for part in auth_data.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                auth_fields[k] = v
        session.set_login_config(LoginConfig(url=auth_url, data=auth_fields))

    console.print(BANNER)
    base_url = url.rstrip("/")
    total_stages = 5 - (1 if skip_dirbrute else 0) - (1 if skip_active else 0)
    stage_num = 0

    async def run() -> None:
        nonlocal stage_num
        active_result = None

        # ── Auto-authentication via SessionManager ────────────────
        if auth_url and auth_data:
            console.print(f"  [cyan]Authenticating to {auth_url}...[/cyan]")
            client = await engine.get_client()
            success = await session.ensure_authenticated(client)
            status_text = "[green]success[/green]" if success else "[red]failed[/red]"
            console.print(f"    Login: {status_text}")
            cookies = session.get_cookies()
            if cookies:
                console.print(f"    [dim]Session cookies: {', '.join(cookies.keys())}[/dim]")

        # ── Stage 1: Spider ──────────────────────────────────────
        stage_num += 1
        spider_mode = "Browser" if browser else "HTML"
        console.rule(f"[cyan]Stage {stage_num}/{total_stages}: Spider ({spider_mode})[/cyan]")
        console.print(f"  Target: {url}  |  Depth: {depth}  |  Threads: {threads}")

        use_browser = browser
        if use_browser:
            try:
                from .modules.browser_spider import BrowserSpider
                bsp = BrowserSpider(db, config, session=session)
                with console.status(f"[cyan]Browser crawling {url}...[/cyan]"):
                    spider_stats = await bsp.crawl(
                        start_urls=[url],
                        max_depth=depth,
                        concurrency=min(threads, 5),
                    )
                stats = bsp.stats
                forms_found = bsp.forms_found
            except ImportError:
                console.print("  [yellow]Playwright not installed, falling back to HTML spider.[/yellow]")
                use_browser = False

        if not use_browser:
            from .modules.spider import Spider
            sp = Spider(engine, db, config)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[cyan]{task.completed} URLs[/cyan]"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"Spidering {url}", total=None)

                async def on_spider_url(discovered_url: str, resp: object, d: int) -> None:
                    progress.update(task, advance=1, description=f"[d={d}] {discovered_url[:70]}")

                spider_stats = await sp.crawl(
                    start_urls=[url],
                    max_depth=depth,
                    concurrency=threads,
                    callback=on_spider_url,
                )

            stats = sp.stats
            forms_found = sp.forms_found

        console.print(f"  [green]Done:[/green] {stats['visited']} URLs | {stats['links_found']} links | {stats['forms']} forms")

        # Save discovered forms (HTML spider — BrowserSpider saves its own)
        if not use_browser:
            for form in forms_found:
                db.save_form(
                    url=form.get("found_on", url),
                    action=form["action"],
                    method=form["method"],
                    inputs=form["inputs"],
                    found_on=form.get("found_on", url),
                )

        # ── Stage 2: Dirbrute ────────────────────────────────────
        if not skip_dirbrute:
            stage_num += 1
            console.rule(f"[cyan]Stage {stage_num}/{total_stages}: Directory Bruteforce[/cyan]")

            # Load wordlist
            if wordlist and Path(wordlist).exists():
                words = [l.strip() for l in Path(wordlist).read_text().splitlines() if l.strip() and not l.startswith("#")]
            else:
                bundled = Path(__file__).parent / "wordlists" / "dirs.txt"
                if bundled.exists():
                    words = [l.strip() for l in bundled.read_text().splitlines() if l.strip() and not l.startswith("#")]
                else:
                    words = []

            if words:
                # Build paths with extensions
                exts = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()] if extensions else []
                paths: list[str] = []
                for w in words:
                    paths.append(w)
                    for ext in exts:
                        paths.append(f"{w}.{ext}")

                console.print(f"  Paths: {len(paths)} ({len(words)} words + {len(exts)} extensions)")
                dirbrute_found = 0
                dirbrute_requests = 0
                sem = asyncio.Semaphore(threads)

                async def check_path(path: str) -> None:
                    nonlocal dirbrute_found, dirbrute_requests
                    test_url = f"{base_url}/{path.lstrip('/')}"
                    req = HttpRequest(method="GET", url=test_url, headers={"User-Agent": config.user_agent})
                    async with sem:
                        resp = await engine.send(req)
                        dirbrute_requests += 1
                    if resp.status_code in (200, 201, 204, 301, 302, 307, 401, 403):
                        dirbrute_found += 1
                        db.add_sitemap_url(
                            url=test_url,
                            status_code=resp.status_code,
                            content_type=resp.content_type,
                            discovered_from="dirbrute",
                            depth=0,
                        )

                with console.status(f"[cyan]Bruteforcing {len(paths)} paths...[/cyan]"):
                    dir_tasks = [asyncio.create_task(check_path(p)) for p in paths]
                    await asyncio.gather(*dir_tasks, return_exceptions=True)

                console.print(f"  [green]Done:[/green] {dirbrute_found} found | {dirbrute_requests} requests")
            else:
                console.print("  [yellow]No wordlist available, skipping.[/yellow]")

        # ── Stage 3: Passive Scan ────────────────────────────────
        stage_num += 1
        console.rule(f"[cyan]Stage {stage_num}/{total_stages}: Passive Scan[/cyan]")

        passive_scanner = PassiveScanner(db)
        with console.status("[cyan]Analyzing captured traffic...[/cyan]"):
            passive_findings = passive_scanner.scan_all_history()

        console.print(f"  [green]Done:[/green] {len(passive_findings)} findings from passive analysis")

        # ── Stage 4: Active Scan ─────────────────────────────────
        if not skip_active:
            stage_num += 1
            console.rule(f"[cyan]Stage {stage_num}/{total_stages}: Active Scan[/cyan]")

            # Session health check before active scanning
            if session.is_authenticated:
                sitemap_urls = db.get_sitemap_urls()
                check_url = sitemap_urls[0] if sitemap_urls else url
                client = await engine.get_client()
                alive = await session.check_session_alive(client, check_url)
                if not alive:
                    console.print("  [yellow]Session expired — re-authenticating...[/yellow]")
                    await session.ensure_authenticated(client)

            from .modules.active_scanner import ActiveScanner

            active_scanner = ActiveScanner(engine, db, config, passive_scanner=passive_scanner)
            active_count = 0

            def on_active_finding(f: object) -> None:
                nonlocal active_count
                active_count += 1
                finding = f  # type: ignore
                sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
                style = SEVERITY_STYLES.get(sev, "dim")
                console.print(f"    [{style}][{sev.upper()}][/{style}] {finding.title}")

            active_result = await active_scanner.scan(concurrency=threads, callback=on_active_finding)
            console.print(f"  [green]Done:[/green] {active_result.requests_sent} requests | "
                          f"{active_result.urls_tested} URLs tested | {len(active_result.findings)} findings | "
                          f"{active_result.elapsed_seconds:.1f}s")

            # ── DAST Coverage Table ──
            if active_result.dast_coverage:
                console.print()
                dast_table = Table(title="DAST Coverage — Active Testing Performed", border_style="cyan")
                dast_table.add_column("Attack Category", style="bold", ratio=2)
                dast_table.add_column("Probes Sent", justify="right", style="cyan")
                dast_table.add_column("Params Tested", justify="right")
                dast_table.add_column("URLs Tested", justify="right")
                dast_table.add_column("Vulns Found", justify="right")

                for cat, cov in active_result.dast_coverage.items():
                    if cov.probes_sent == 0:
                        continue
                    vuln_style = "bold red" if cov.findings_count > 0 else "green"
                    vuln_text = f"[{vuln_style}]{cov.findings_count}[/{vuln_style}]"
                    dast_table.add_row(
                        cat,
                        str(cov.probes_sent),
                        str(cov.params_tested),
                        str(cov.urls_tested),
                        vuln_text,
                    )

                # Totals row
                total_probes = active_result.total_probes
                total_params = active_result.total_params_tested
                total_urls = sum(c.urls_tested for c in active_result.dast_coverage.values())
                total_vulns = sum(c.findings_count for c in active_result.dast_coverage.values())
                vuln_style = "bold red" if total_vulns > 0 else "green"
                dast_table.add_row(
                    "[bold]TOTAL[/bold]",
                    f"[bold]{total_probes}[/bold]",
                    f"[bold]{total_params}[/bold]",
                    f"[bold]{total_urls}[/bold]",
                    f"[{vuln_style}][bold]{total_vulns}[/bold][/{vuln_style}]",
                )
                console.print(dast_table)

        # ── Stage 5: Export Report ───────────────────────────────
        stage_num += 1
        console.rule(f"[cyan]Stage {stage_num}/{total_stages}: Generate Report[/cyan]")

        findings_data = db.get_findings()
        if findings_data:
            from .utils.reporter import Reporter

            stats_data = db.get_stats()
            sitemap_data = db.get_sitemap()

            # Serialize DAST coverage for the report
            dast_cov_data: dict = {}
            if not skip_active and active_result and active_result.dast_coverage:
                from dataclasses import asdict
                dast_cov_data = {cat: asdict(cov) for cat, cov in active_result.dast_coverage.items()}

            reporter = Reporter(
                findings=findings_data,
                stats=stats_data,
                sitemap=sitemap_data,
                project_name=f"justdastit scan — {url}",
                dast_coverage=dast_cov_data,
            )

            ts = int(time.time())
            if report:
                outfile = report
            else:
                host = urlparse(url).hostname or "target"
                outfile = f"justdastit_{host}_{ts}.{fmt}"

            if fmt == "json":
                reporter.to_json(outfile)
            elif fmt == "html":
                reporter.to_html(outfile)
            else:
                reporter.to_markdown(outfile)

            console.print(f"  [green]Report saved:[/green] {outfile}")
        else:
            console.print("  [dim]No findings to report.[/dim]")

        await engine.close()

    # ── Run pipeline ─────────────────────────────────────────────
    start_time = time.time()
    asyncio.run(run())
    elapsed = time.time() - start_time

    # ── Final summary ────────────────────────────────────────────
    final_stats = db.get_stats()
    console.print()
    console.rule("[green]Autopilot Complete[/green]")

    summary = Table(show_header=False, border_style="green")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="white")
    summary.add_row("Target", url)
    summary.add_row("Total Time", f"{elapsed:.1f}s")
    summary.add_row("Requests Sent", str(final_stats["total_requests"]))
    summary.add_row("Sitemap URLs", str(final_stats["sitemap_urls"]))
    summary.add_row("Forms Found", str(final_stats.get("total_forms", 0)))
    summary.add_row("Total Findings", str(final_stats["total_findings"]))

    if final_stats["findings_by_severity"]:
        sev_parts = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = final_stats["findings_by_severity"].get(sev, 0)
            if count:
                style = SEVERITY_STYLES.get(sev, "dim")
                sev_parts.append(f"[{style}]{sev.upper()}: {count}[/{style}]")
        if sev_parts:
            summary.add_row("Severity Breakdown", " | ".join(sev_parts))

    console.print(summary)


# ── Decode / Encode / Hash ────────────────────────────────────────────


@cli.command()
@click.argument("data")
@click.option("-t", "--type", "decode_type", default=None, help=f"Decoder: {', '.join(DECODERS.keys())}.")
def decode(data: str, decode_type: Optional[str]) -> None:
    """Decode data (auto-detects encoding if no type specified).

    \b
    Examples:
      justdastit decode "SGVsbG8gV29ybGQ="
      justdastit decode "%3Cscript%3E" -t url
      justdastit decode "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" -t jwt
    """
    if decode_type:
        if decode_type not in DECODERS:
            console.print(f"[red]Unknown decoder: {decode_type}[/red]")
            console.print(f"Available: {', '.join(DECODERS.keys())}")
            return
        try:
            result = DECODERS[decode_type](data)
            console.print(str(result))
        except Exception as e:
            console.print(f"[red]Decode error: {e}[/red]")
    else:
        results = smart_decode(data)
        if results:
            table = Table(show_header=False, border_style="dim")
            table.add_column("Type", style="cyan")
            table.add_column("Result")
            for name, decoded in results:
                table.add_row(name, str(decoded))
            console.print(table)
        else:
            console.print("[dim]No successful decodings found.[/dim]")


@cli.command()
@click.argument("data")
@click.option("-t", "--type", "encode_type", required=True, help=f"Encoder: {', '.join(ENCODERS.keys())}.")
def encode(data: str, encode_type: str) -> None:
    """Encode data with the specified encoder.

    \b
    Examples:
      justdastit encode "<script>alert(1)</script>" -t url
      justdastit encode "Hello World" -t b64
      justdastit encode "test" -t hex
    """
    if encode_type not in ENCODERS:
        console.print(f"[red]Unknown encoder: {encode_type}[/red]")
        console.print(f"Available: {', '.join(ENCODERS.keys())}")
        return
    console.print(ENCODERS[encode_type](data))


@cli.command(name="hash")
@click.argument("data")
@click.option("-t", "--type", "hash_type", default=None, help=f"Hash: {', '.join(HASHERS.keys())}.")
def hash_cmd(data: str, hash_type: Optional[str]) -> None:
    """Hash data (shows all algorithms if no type specified).

    \b
    Examples:
      justdastit hash "password123"
      justdastit hash "admin" -t md5
      justdastit hash "secret" -t sha256
    """
    if hash_type:
        if hash_type not in HASHERS:
            console.print(f"[red]Unknown hash: {hash_type}[/red]")
            return
        console.print(HASHERS[hash_type](data))
    else:
        table = Table(show_header=False, border_style="dim")
        table.add_column("Algorithm", style="cyan")
        table.add_column("Hash")
        for name, func in HASHERS.items():
            table.add_row(name, func(data))
        console.print(table)


# ── History / Findings / Sitemap / Stats ──────────────────────────────


@cli.command()
@click.option("-n", "--limit", type=int, default=50, help="Number of requests to show.")
@click.option("-f", "--filter", "url_filter", default=None, help="URL filter pattern.")
@click.pass_context
def history(ctx: click.Context, limit: int, url_filter: Optional[str]) -> None:
    """Show HTTP request history.

    \b
    Examples:
      justdastit history
      justdastit history -n 100
      justdastit history -f "api/users"
    """
    _, db = _load_config(ctx)
    rows = db.get_requests(limit=limit, url_filter=url_filter or "")
    if not rows:
        console.print("[dim]No requests captured yet.[/dim]")
        return

    table = Table(title=f"Request History (last {len(rows)})", border_style="dim")
    table.add_column("ID", style="bold", width=6)
    table.add_column("Method", style="yellow", width=7)
    table.add_column("URL", ratio=1)
    table.add_column("Tags", style="dim", width=20)

    for r in rows:
        tags = json.loads(r.get("tags", "[]"))
        tag_str = ", ".join(tags) if tags else ""
        table.add_row(str(r["id"]), r["method"], r["url"][:100], tag_str)

    console.print(table)


@cli.command()
@click.option("-s", "--severity", default=None, help="Filter by severity (critical/high/medium/low/info).")
@click.pass_context
def findings(ctx: click.Context, severity: Optional[str]) -> None:
    """Show security findings.

    \b
    Examples:
      justdastit findings
      justdastit findings -s high
      justdastit findings -s critical
    """
    _, db = _load_config(ctx)
    rows = db.get_findings(severity=severity)
    if not rows:
        console.print("[dim]No findings yet.[/dim]")
        return

    table = Table(title=f"Security Findings ({len(rows)})", border_style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Title", ratio=1)
    table.add_column("URL", ratio=1)
    table.add_column("CWE", width=10)

    for f in rows:
        sev = f.get("severity", "info")
        style = SEVERITY_STYLES.get(sev, "dim")
        table.add_row(
            f"[{style}]{sev.upper()}[/{style}]",
            f["title"],
            f["url"][:80],
            f.get("cwe") or "",
        )

    console.print(table)


@cli.command()
@click.pass_context
def sitemap(ctx: click.Context) -> None:
    """Show discovered URL sitemap.

    \b
    Examples:
      justdastit sitemap
    """
    _, db = _load_config(ctx)
    urls = db.get_sitemap()
    if not urls:
        console.print("[dim]No URLs in sitemap yet.[/dim]")
        return

    table = Table(title=f"Sitemap ({len(urls)} URLs)", border_style="dim")
    table.add_column("Status", width=6)
    table.add_column("URL", ratio=1)
    table.add_column("Content-Type", style="dim", width=30)

    for u in urls:
        code = u.get("status_code") or "?"
        style = status_style(int(code)) if str(code).isdigit() else "dim"
        table.add_row(f"[{style}]{code}[/{style}]", u["url"][:120], (u.get("content_type") or "")[:30])

    console.print(table)


@cli.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show project statistics.

    \b
    Examples:
      justdastit stats
    """
    _, db = _load_config(ctx)
    s = db.get_stats()

    table = Table(title="Project Statistics", show_header=False, border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Requests Captured", str(s["total_requests"]))
    table.add_row("Sitemap URLs", str(s["sitemap_urls"]))
    table.add_row("Forms Discovered", str(s.get("total_forms", 0)))
    table.add_row("Total Findings", str(s["total_findings"]))
    console.print(table)

    if s["findings_by_severity"]:
        sev_table = Table(title="Findings by Severity", border_style="dim")
        sev_table.add_column("Severity", width=12)
        sev_table.add_column("Count", width=8, justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = s["findings_by_severity"].get(sev, 0)
            if count:
                style = SEVERITY_STYLES.get(sev, "dim")
                sev_table.add_row(f"[{style}]{sev.upper()}[/{style}]", str(count))
        console.print(sev_table)


# ── Export ────────────────────────────────────────────────────────────


@cli.command()
@click.option("-f", "--format", "fmt", default="md", type=click.Choice(["json", "md", "html"]), help="Report format.")
@click.option("-o", "--output", default=None, help="Output file path (auto-generated if not set).")
@click.pass_context
def export(ctx: click.Context, fmt: str, output: Optional[str]) -> None:
    """Export findings as a report (HTML, Markdown, or JSON).

    \b
    Examples:
      justdastit export
      justdastit export -f html -o report.html
      justdastit export -f json
      justdastit export -f md -o findings.md
    """
    _, db = _load_config(ctx)
    findings_data = db.get_findings()
    if not findings_data:
        console.print("[dim]No findings to export.[/dim]")
        return

    from .utils.reporter import Reporter

    stats_data = db.get_stats()
    sitemap_data = db.get_sitemap()
    reporter = Reporter(
        findings=findings_data,
        stats=stats_data,
        sitemap=sitemap_data,
        project_name=f"justdastit scan",
    )

    ts = int(time.time())
    if fmt == "json":
        outfile = output or f"justdastit_report_{ts}.json"
        reporter.to_json(outfile)
    elif fmt == "html":
        outfile = output or f"justdastit_report_{ts}.html"
        reporter.to_html(outfile)
    else:
        outfile = output or f"justdastit_report_{ts}.md"
        reporter.to_markdown(outfile)

    console.print(f"[green]Report exported:[/green] {outfile}")
    console.print(f"  Format: {fmt.upper()} | Findings: {len(findings_data)}")


# ── Shell (Interactive REPL) ──────────────────────────────────────────


@cli.command()
@click.pass_context
def shell(ctx: click.Context) -> None:
    """Launch interactive REPL mode.

    Browse history, modify and resend requests, run scans — all without restarting.

    \b
    Examples:
      justdastit shell
    """
    config, db = _load_config(ctx)

    console.print(BANNER)
    console.print("[cyan]Interactive mode. Type 'help' for commands, 'exit' to quit.[/cyan]\n")

    commands_help = {
        "help": "Show this help",
        "history [n]": "Show last n requests (default 20)",
        "repeat <id>": "Resend request by ID",
        "findings": "Show all findings",
        "sitemap": "Show sitemap",
        "stats": "Show project stats",
        "scan": "Run passive scan",
        "decode <data>": "Smart decode data",
        "encode <type> <data>": "Encode data",
        "hash <data>": "Hash data with all algorithms",
        "exit / quit": "Exit shell",
    }

    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import InMemoryHistory

        session: PromptSession[str] = PromptSession(history=InMemoryHistory())
        readline_available = True
    except ImportError:
        readline_available = False

    while True:
        try:
            if readline_available:
                line = session.prompt("justdastit> ")  # type: ignore[union-attr]
            else:
                line = input("justdastit> ")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd in ("exit", "quit", "q"):
            console.print("[dim]Goodbye.[/dim]")
            break
        elif cmd == "help":
            help_table = Table(show_header=False, border_style="dim")
            help_table.add_column("Command", style="cyan")
            help_table.add_column("Description")
            for c, d in commands_help.items():
                help_table.add_row(c, d)
            console.print(help_table)
        elif cmd == "history":
            limit = int(parts[1]) if len(parts) > 1 else 20
            rows = db.get_requests(limit=limit)
            if rows:
                table = Table(border_style="dim")
                table.add_column("ID", width=6)
                table.add_column("Method", width=7)
                table.add_column("URL", ratio=1)
                for r in rows:
                    table.add_row(str(r["id"]), r["method"], r["url"][:100])
                console.print(table)
            else:
                console.print("[dim]No requests yet.[/dim]")
        elif cmd == "repeat" and len(parts) > 1:
            try:
                rid = int(parts[1])
                engine = _setup_engine(config)
                repeater = Repeater(engine, db)

                async def do_repeat() -> None:
                    resp = await repeater.replay(rid)
                    if resp:
                        style = status_style(resp.status_code)
                        console.print(f"[{style}]{resp.status_code}[/{style}] | {resp.content_length}B | {resp.elapsed_ms:.1f}ms")
                    else:
                        console.print(f"[red]Request {rid} not found[/red]")
                    await engine.close()

                asyncio.run(do_repeat())
            except ValueError:
                console.print("[red]Invalid request ID[/red]")
        elif cmd == "findings":
            rows = db.get_findings()
            if rows:
                for f in rows:
                    sev = f.get("severity", "info")
                    style = SEVERITY_STYLES.get(sev, "dim")
                    console.print(f"  [{style}][{sev.upper()}][/{style}] {f['title']} — {f['url'][:60]}")
            else:
                console.print("[dim]No findings.[/dim]")
        elif cmd == "sitemap":
            urls = db.get_sitemap()
            for u in urls[:50]:
                console.print(f"  {u.get('status_code', '?')} {u['url'][:100]}")
        elif cmd == "stats":
            s = db.get_stats()
            console.print(f"  Requests: {s['total_requests']} | URLs: {s['sitemap_urls']} | Findings: {s['total_findings']}")
        elif cmd == "scan":
            scanner = PassiveScanner(db)
            findings_list = scanner.scan_all_history()
            console.print(f"[green]Scan complete:[/green] {len(findings_list)} finding(s)")
        elif cmd == "decode" and len(parts) > 1:
            data = " ".join(parts[1:])
            results = smart_decode(data)
            for name, decoded in results:
                console.print(f"  [cyan]{name}:[/cyan] {decoded}")
        elif cmd == "encode" and len(parts) > 2:
            etype = parts[1]
            data = " ".join(parts[2:])
            if etype in ENCODERS:
                console.print(ENCODERS[etype](data))
            else:
                console.print(f"[red]Unknown encoder: {etype}[/red]")
        elif cmd == "hash" and len(parts) > 1:
            data = " ".join(parts[1:])
            for name, func in HASHERS.items():
                console.print(f"  [cyan]{name}:[/cyan] {func(data)}")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]. Type 'help' for available commands.")

    db.close()


# ── MCP Server ────────────────────────────────────────────────────────


@cli.command(name="mcp-server")
@click.pass_context
def mcp_server(ctx: click.Context) -> None:
    """Start justdastit as an MCP server for AI-driven scanning.

    \b
    Examples:
      justdastit mcp-server
    """
    try:
        from .mcp_server import create_server

        server = create_server(db_path=ctx.obj.get("db", "justdastit.db"))
        server.run()
    except ImportError:
        console.print("[red]fastmcp not installed.[/red] Install with: pip install justdastit[mcp]")


# ── Entry Point ───────────────────────────────────────────────────────


def main() -> None:
    cli(auto_envvar_prefix="JUSTDASTIT")
