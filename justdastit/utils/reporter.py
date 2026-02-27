"""justdastit - Report generation: HTML, Markdown, JSON."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

__all__ = ["Reporter"]

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class Reporter:
    """Generate security reports from scan findings."""

    def __init__(
        self,
        findings: list[dict],
        stats: dict,
        sitemap: list[dict] | None = None,
        project_name: str = "justdastit scan",
        dast_coverage: dict | None = None,
    ) -> None:
        self.findings = findings
        self.stats = stats
        self.sitemap = sitemap or []
        self.project_name = project_name
        self.generated_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.dast_coverage = dast_coverage or {}

    def to_json(self, output_path: Optional[str] = None) -> str:
        """Export findings as JSON."""
        data = {
            "project": self.project_name,
            "generated_at": self.generated_at,
            "stats": self.stats,
            "dast_coverage": self.dast_coverage,
            "findings": self.findings,
            "sitemap_urls": len(self.sitemap),
        }
        output = json.dumps(data, indent=2, default=str)
        if output_path:
            Path(output_path).write_text(output)
        return output

    def to_markdown(self, output_path: Optional[str] = None) -> str:
        """Export findings as Markdown."""
        lines = [
            f"# {self.project_name} — Security Report",
            f"",
            f"**Generated:** {self.generated_at}",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total Requests | {self.stats.get('total_requests', 0)} |",
            f"| Sitemap URLs | {self.stats.get('sitemap_urls', 0)} |",
            f"| Total Findings | {self.stats.get('total_findings', 0)} |",
            f"| Forms Discovered | {self.stats.get('total_forms', 0)} |",
            f"",
        ]

        severity_counts = self.stats.get("findings_by_severity", {})
        if severity_counts:
            lines.append("### Severity Breakdown")
            lines.append("")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_counts.get(sev, 0)
                if count:
                    emoji = {"critical": "!!!", "high": "!!", "medium": "!", "low": "-", "info": "i"}.get(sev, "")
                    lines.append(f"- **{sev.upper()}**: {count}")
            lines.append("")

        if self.dast_coverage:
            lines.append("## DAST Coverage — Active Testing Performed")
            lines.append("")
            lines.append("| Attack Category | Probes Sent | Params Tested | URLs Tested | Vulns Found |")
            lines.append("|-----------------|-------------|---------------|-------------|-------------|")
            total_p = total_pa = total_u = total_v = 0
            for cat, cov in self.dast_coverage.items():
                p = cov.get("probes_sent", 0)
                if p == 0:
                    continue
                pa = cov.get("params_tested", 0)
                u = cov.get("urls_tested", 0)
                v = cov.get("findings_count", 0)
                total_p += p; total_pa += pa; total_u += u; total_v += v
                lines.append(f"| {cat} | {p:,} | {pa:,} | {u:,} | {v} |")
            lines.append(f"| **TOTAL** | **{total_p:,}** | **{total_pa:,}** | **{total_u:,}** | **{total_v}** |")
            lines.append("")

        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in self.findings if f.get("severity") == sev]
            if not sev_findings:
                continue
            lines.append(f"## {sev.upper()} ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                lines.append(f"### {f['title']}")
                lines.append("")
                lines.append(f"- **URL:** `{f['url']}`")
                if f.get("detail"):
                    lines.append(f"- **Detail:** {f['detail']}")
                if f.get("evidence"):
                    lines.append(f"- **Evidence:** `{f['evidence'][:300]}`")
                if f.get("cwe"):
                    lines.append(f"- **CWE:** {f['cwe']}")
                if f.get("remediation"):
                    lines.append(f"- **Remediation:** {f['remediation']}")
                lines.append("")

        output = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(output)
        return output

    def to_html(self, output_path: Optional[str] = None) -> str:
        """Export findings as a self-contained HTML report."""
        try:
            import jinja2
            template_path = TEMPLATE_DIR / "report.html"
            if template_path.exists():
                env = jinja2.Environment(
                    loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
                    autoescape=True,
                )
                template = env.get_template("report.html")
                output = template.render(
                    project_name=self.project_name,
                    generated_at=self.generated_at,
                    stats=self.stats,
                    findings=self.findings,
                    sitemap=self.sitemap,
                    severity_order=["critical", "high", "medium", "low", "info"],
                )
            else:
                output = self._fallback_html()
        except ImportError:
            output = self._fallback_html()

        if output_path:
            Path(output_path).write_text(output)
        return output

    def _fallback_html(self) -> str:
        """Generate HTML without Jinja2."""
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
            "info": "#6b7280",
        }

        findings_html = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in self.findings if f.get("severity") == sev]
            if not sev_findings:
                continue
            color = severity_colors.get(sev, "#6b7280")
            findings_html += f'<h2 style="color:{color}">{sev.upper()} ({len(sev_findings)})</h2>\n'
            for f in sev_findings:
                evidence_html = ""
                if f.get("evidence"):
                    esc_evidence = f["evidence"][:500].replace("<", "&lt;").replace(">", "&gt;")
                    evidence_html = f'<pre class="evidence">{esc_evidence}</pre>'
                esc_url = f["url"].replace("<", "&lt;").replace(">", "&gt;")
                esc_title = f["title"].replace("<", "&lt;").replace(">", "&gt;")
                esc_detail = (f.get("detail") or "").replace("<", "&lt;").replace(">", "&gt;")
                findings_html += f"""
<div class="finding" style="border-left:4px solid {color}">
  <h3>{esc_title}</h3>
  <p><strong>URL:</strong> <code>{esc_url}</code></p>
  <p>{esc_detail}</p>
  {evidence_html}
  {"<p><em>" + f["cwe"] + "</em></p>" if f.get("cwe") else ""}
</div>
"""

        stats = self.stats
        severity_counts = stats.get("findings_by_severity", {})
        chart_bars = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                color = severity_colors.get(sev, "#6b7280")
                width = min(count * 30, 400)
                chart_bars += f'<div class="bar" style="background:{color};width:{width}px">{sev.upper()}: {count}</div>\n'

        # DAST Coverage section
        dast_html = ""
        if self.dast_coverage:
            dast_rows = ""
            total_probes = 0
            total_params = 0
            total_urls = 0
            total_vulns = 0
            for cat, cov in self.dast_coverage.items():
                if cov.get("probes_sent", 0) == 0:
                    continue
                probes = cov.get("probes_sent", 0)
                params = cov.get("params_tested", 0)
                urls = cov.get("urls_tested", 0)
                vulns = cov.get("findings_count", 0)
                total_probes += probes
                total_params += params
                total_urls += urls
                total_vulns += vulns
                vuln_color = "#ef4444" if vulns > 0 else "#22c55e"
                dast_rows += f"""<tr>
  <td>{cat}</td><td style="text-align:right">{probes:,}</td>
  <td style="text-align:right">{params:,}</td><td style="text-align:right">{urls:,}</td>
  <td style="text-align:right;color:{vuln_color};font-weight:bold">{vulns}</td>
</tr>"""
            vuln_color = "#ef4444" if total_vulns > 0 else "#22c55e"
            dast_rows += f"""<tr style="font-weight:bold;border-top:2px solid #475569">
  <td>TOTAL</td><td style="text-align:right">{total_probes:,}</td>
  <td style="text-align:right">{total_params:,}</td><td style="text-align:right">{total_urls:,}</td>
  <td style="text-align:right;color:{vuln_color}">{total_vulns}</td>
</tr>"""
            dast_html = f"""
<h2 style="color:#38bdf8">DAST Coverage &mdash; Active Testing Performed</h2>
<p style="color:#94a3b8;margin-bottom:1rem">The following injection and attack tests were executed against discovered endpoints:</p>
<table class="dast-table">
<thead><tr><th>Attack Category</th><th>Probes Sent</th><th>Params Tested</th><th>URLs Tested</th><th>Vulns Found</th></tr></thead>
<tbody>{dast_rows}</tbody>
</table>
"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{self.project_name} — Security Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto}}
h1{{color:#38bdf8;font-size:2rem;margin-bottom:.5rem}}
h2{{margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid #334155}}
h3{{color:#f1f5f9;margin-bottom:.5rem}}
.meta{{color:#94a3b8;margin-bottom:2rem}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:2rem 0}}
.stat{{background:#1e293b;padding:1.5rem;border-radius:8px;text-align:center}}
.stat .num{{font-size:2rem;font-weight:bold;color:#38bdf8}}
.stat .label{{color:#94a3b8;font-size:.875rem}}
.chart{{margin:2rem 0}}
.bar{{padding:.5rem 1rem;margin:.25rem 0;border-radius:4px;color:white;font-weight:bold;font-size:.875rem}}
.finding{{background:#1e293b;padding:1.5rem;margin:1rem 0;border-radius:8px}}
.finding p{{margin:.5rem 0}}
code{{background:#334155;padding:.15rem .4rem;border-radius:3px;font-size:.875rem}}
pre.evidence{{background:#0f172a;padding:1rem;border-radius:4px;overflow-x:auto;font-size:.8rem;margin-top:.5rem}}
.dast-table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:8px;overflow:hidden;margin:1rem 0}}
.dast-table th{{background:#334155;padding:.75rem 1rem;text-align:left;font-size:.875rem;color:#94a3b8}}
.dast-table td{{padding:.6rem 1rem;border-bottom:1px solid #334155;font-size:.875rem}}
.dast-table tr:hover{{background:#273549}}
.footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #334155;color:#64748b;font-size:.8rem;text-align:center}}
</style>
</head>
<body>
<div class="container">
<h1>justdastit Security Report</h1>
<p class="meta">{self.project_name} &mdash; Generated {self.generated_at}</p>

<div class="stats">
  <div class="stat"><div class="num">{stats.get('total_requests',0)}</div><div class="label">Requests</div></div>
  <div class="stat"><div class="num">{stats.get('sitemap_urls',0)}</div><div class="label">URLs</div></div>
  <div class="stat"><div class="num">{stats.get('total_findings',0)}</div><div class="label">Findings</div></div>
  <div class="stat"><div class="num">{stats.get('total_forms',0)}</div><div class="label">Forms</div></div>
</div>

<div class="chart">{chart_bars}</div>

{dast_html}

{findings_html}

<div class="footer">
  Generated by <strong>justdastit</strong> — The Burp You Can Afford &mdash;
  <a href="https://github.com/snailsploit/justdastit" style="color:#38bdf8">github.com/snailsploit/justdastit</a>
</div>
</div>
</body>
</html>"""
