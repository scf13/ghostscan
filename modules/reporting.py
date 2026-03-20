#!/usr/bin/env python3
"""
GhostScan - Reporting Module v2
Outputs: Markdown, HTML, JSON, PDF (via ReportLab or WeasyPrint).
"""

import json
import os
import re
import html as html_mod
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, PageBreak, HRFlowable)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from modules.utils import log, Colors


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLORS_HEX = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#27ae60",
    "INFO":     "#7f8c8d",
}

SEVERITY_BADGE_CSS = {
    "CRITICAL": "background:#c0392b;color:#fff",
    "HIGH":     "background:#e67e22;color:#fff",
    "MEDIUM":   "background:#f39c12;color:#fff",
    "LOW":      "background:#27ae60;color:#fff",
    "INFO":     "background:#7f8c8d;color:#fff",
}


class ReportingModule:
    def __init__(self, config: dict, all_results: dict):
        self.config = config
        self.results = all_results
        self.target = config["target"]

        # Always resolve output dir to absolute path
        raw_out = config.get("output", "ghostscan_results")
        self.output_dir = Path(raw_out).expanduser().resolve()
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback to home directory if permission denied
            self.output_dir = Path.home() / "ghostscan_results"
            self.output_dir.mkdir(parents=True, exist_ok=True)
            log(f"  Output dir permission denied — using: {self.output_dir}", Colors.YELLOW)
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.safe_target = re.sub(r"[^\w\-.]", "_", self.target)
        self.all_findings = self._collect_all_findings()

    # ── PUBLIC API ────────────────────────────────────────────────────────────

    def generate(self, fmt: str = "both"):
        """fmt: markdown | html | pdf | json | both | all"""
        paths = {}
        session_path = self._save_session_json()
        paths["json"] = session_path

        if fmt in ("markdown", "both", "all", "md"):
            p = self._write_markdown()
            paths["markdown"] = p
            log(f"  Markdown report: {p}", Colors.GREEN)

        if fmt in ("html", "all"):
            p = self._write_html()
            paths["html"] = p
            log(f"  HTML report:     {p}", Colors.GREEN)

        if fmt in ("pdf", "both", "all"):
            if HAS_REPORTLAB:
                p = self._write_pdf()
                paths["pdf"] = p
                log(f"  PDF report:      {p}", Colors.GREEN)
            else:
                # Fall back to HTML
                p = self._write_html()
                paths["html"] = p
                log(f"  PDF skipped (reportlab missing) — HTML: {p}", Colors.YELLOW)

        return paths

    # ── SESSION JSON ──────────────────────────────────────────────────────────

    def _save_session_json(self) -> str:
        path = self.output_dir / f"session_{self.ts}.json"
        payload = {
            "meta": {
                "target":            self.target,
                "timestamp":         self.ts,
                "ghostscan_version": "3.0",
                "output_dir":        str(self.output_dir),
            },
            "results":   self.results,
            "findings":  self.all_findings,
            "summary": {
                sev: sum(1 for f in self.all_findings if f.get("severity","").upper() == sev)
                for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
            },
        }
        # Also include intelligence correlations if present
        if "intelligence" in self.results:
            payload["correlations"] = self.results["intelligence"].get("correlations", [])
            payload["ranked_targets"] = self.results["intelligence"].get("ranked_targets", [])

        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        log(f"  Session saved → {path}", Colors.DIM)
        return str(path)

    # ── MARKDOWN ──────────────────────────────────────────────────────────────

    def _write_markdown(self) -> str:
        path = self.output_dir / f"ghostscan_{self.safe_target}_{self.ts}.md"
        lines = self._build_markdown_lines()
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return str(path)

    def _build_markdown_lines(self) -> list:
        lines = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = self._severity_summary()

        lines += [
            f"# GhostScan Security Assessment Report",
            f"",
            f"| Field       | Value |",
            f"|-------------|-------|",
            f"| **Target**  | `{self.target}` |",
            f"| **Date**    | {now} |",
            f"| **Tool**    | GhostScan v2.0 — Kali Linux Framework |",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = summary.get(sev, 0)
            if c:
                lines.append(f"| **{sev}** | {c} |")
        lines += ["", "---", ""]

        # Findings table
        lines += ["## Findings", ""]
        sorted_findings = sorted(self.all_findings,
                                  key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO")
            lines += [
                f"### [{i}] `{sev}` — {f.get('title', '')}",
                f"",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Category** | {f.get('category', '')} |",
                f"| **Severity** | {sev} |",
            ]
            if f.get("url"):
                lines.append(f"| **URL** | `{f['url']}` |")
            if f.get("detail"):
                lines.append(f"| **Detail** | {f['detail'][:200]} |")
            if f.get("evidence"):
                lines.append(f"| **Evidence** | `{f['evidence'][:120]}` |")
            if f.get("remediation"):
                lines.append(f"| **Fix** | {f['remediation']} |")
            lines += [""]

        # Recon section
        r = self.results.get("recon", {})
        if r:
            lines += ["---", "", "## Reconnaissance", ""]
            dns = r.get("dns_records", {})
            if dns:
                lines += ["### DNS Records", ""]
                for rtype, vals in dns.items():
                    for v in vals:
                        lines.append(f"- `{rtype}` → `{v}`")
                lines += [""]
            subs = r.get("subdomains", [])
            if subs:
                lines += [f"### Subdomains ({len(subs)} found)", ""]
                for s in subs[:50]:
                    ips = ", ".join(s.get("ips", []))
                    lines.append(f"- `{s['subdomain']}` → {ips}")
                if len(subs) > 50:
                    lines.append(f"- *...and {len(subs)-50} more*")
                lines += [""]
            ports = r.get("open_ports", {})
            if ports:
                lines += ["### Open Ports", ""]
                for host, host_ports in ports.items():
                    lines.append(f"**{host}**")
                    for port, info in sorted(host_ports.items(), key=lambda x: int(x[0])):
                        svc = info.get("service", "")
                        ver = f"{info.get('product','')} {info.get('version','')}".strip()
                        lines.append(f"- `{port}/tcp` {svc} {ver}")
                lines += [""]

        # Web section
        w = self.results.get("web", {})
        if w:
            lines += ["---", "", "## Web Analysis", ""]
            waf = w.get("waf", {})
            if waf.get("waf"):
                lines.append(f"**WAF Detected:** {waf['waf']}")
            tech = w.get("technologies", {})
            if tech:
                for cat, items in tech.items():
                    if items:
                        lines.append(f"**{cat.title()}:** {', '.join(str(i) for i in items[:5])}")
            lines += [""]
            dirs = w.get("dir_brute", [])
            if dirs:
                lines += [f"### Directories Found ({len(dirs)})", ""]
                for d in sorted(dirs, key=lambda x: x.get("status", 0)):
                    lines.append(f"- `{d.get('status')}` `{d.get('path')}` ({d.get('size',0)} bytes)")
                lines += [""]
            secrets = w.get("js_secrets", [])
            if secrets:
                lines += [f"### Secrets in JavaScript ({len(secrets)})", ""]
                for s in secrets:
                    lines.append(f"- **{s['type']}** in `{s['url']}`")
                lines += [""]

        # Workflow section
        lines += [
            "---", "",
            "## Pentest Workflow Reference",
            "",
            "> Auto-generated based on discovered services.",
            "",
        ]
        workflow_md = self._build_workflow_section()
        lines.append(workflow_md)

        lines += [
            "---",
            "",
            f"*Report generated by GhostScan v2.0 on {now}*",
            "*For authorized security assessments only.*",
        ]
        return lines

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _write_html(self) -> str:
        path = self.output_dir / f"ghostscan_{self.safe_target}_{self.ts}.html"
        with open(path, "w") as f:
            f.write(self._build_html())
        return str(path)

    def _build_html(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = self._severity_summary()
        sorted_findings = sorted(self.all_findings,
                                  key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))

        finding_cards = ""
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO")
            badge_css = SEVERITY_BADGE_CSS.get(sev, "background:#333;color:#fff")
            ev = html_mod.escape(f.get("evidence", "")[:200])
            rem = html_mod.escape(f.get("remediation", ""))
            url = html_mod.escape(f.get("url", ""))
            detail = html_mod.escape(f.get("detail", "")[:300])
            title = html_mod.escape(f.get("title", ""))
            finding_cards += f"""
            <div class="card finding-card">
              <div class="card-header">
                <span class="badge" style="{badge_css}">{sev}</span>
                <strong>[{i}] {title}</strong>
              </div>
              <div class="card-body">
                <table class="info-table">
                  <tr><td>Category</td><td>{html_mod.escape(f.get('category',''))}</td></tr>
                  {'<tr><td>URL</td><td><code>' + url + '</code></td></tr>' if url else ''}
                  {'<tr><td>Detail</td><td>' + detail + '</td></tr>' if detail else ''}
                  {'<tr><td>Evidence</td><td><code>' + ev + '</code></td></tr>' if ev else ''}
                  {'<tr><td>Remediation</td><td class="fix">' + rem + '</td></tr>' if rem else ''}
                </table>
              </div>
            </div>"""

        summary_pills = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = summary.get(sev, 0)
            if c:
                col = SEVERITY_COLORS_HEX.get(sev, "#333")
                summary_pills += f'<div class="pill" style="background:{col}">{sev} <span class="pill-count">{c}</span></div>'

        # Port table
        port_rows = ""
        for host, host_ports in self.results.get("recon", {}).get("open_ports", {}).items():
            for port, info in sorted(host_ports.items(), key=lambda x: int(x[0])):
                svc = html_mod.escape(info.get("service", ""))
                ver = html_mod.escape(f"{info.get('product','')} {info.get('version','')}".strip())
                port_rows += f"<tr><td>{host}</td><td>{port}/tcp</td><td>{svc}</td><td>{ver}</td></tr>"

        # Subdomain table
        sub_rows = ""
        for s in self.results.get("recon", {}).get("subdomains", [])[:60]:
            sd = html_mod.escape(s.get("subdomain", ""))
            ips = html_mod.escape(", ".join(s.get("ips", [])))
            src = html_mod.escape(s.get("source", ""))
            sub_rows += f"<tr><td>{sd}</td><td>{ips}</td><td>{src}</td></tr>"

        # Directory table
        dir_rows = ""
        for d in sorted(self.results.get("web", {}).get("dir_brute", []),
                        key=lambda x: x.get("status", 0)):
            status = d.get("status", 0)
            color = "#27ae60" if status == 200 else "#e67e22" if status in [301,302] else "#7f8c8d"
            dir_rows += f'<tr><td style="color:{color};font-weight:bold">{status}</td><td><code>{html_mod.escape(d.get("path",""))}</code></td><td>{d.get("size",0)}</td></tr>'

        # JS secrets
        js_rows = ""
        for s in self.results.get("web", {}).get("js_secrets", []):
            js_rows += f'<tr><td><span class="badge" style="background:#c0392b;color:#fff">{html_mod.escape(s.get("type",""))}</span></td><td><code>{html_mod.escape(s.get("url","")[:80])}</code></td><td><code>{html_mod.escape(s.get("match","")[:80])}</code></td></tr>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GhostScan Report — {html_mod.escape(self.target)}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --radius: 8px;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
         color: var(--text); line-height: 1.6; padding: 24px; }}
  h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 1.3rem; color: var(--accent); border-bottom: 1px solid var(--border);
        padding-bottom: 8px; margin: 32px 0 16px; }}
  h3 {{ font-size: 1.1rem; margin: 20px 0 8px; color: #e6edf3; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 24px; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0 32px; }}
  .pill {{ border-radius: 20px; padding: 8px 18px; font-weight: 700; font-size: .9rem;
           display: flex; align-items: center; gap: 8px; }}
  .pill-count {{ background: rgba(0,0,0,.3); border-radius: 12px; padding: 2px 8px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }}
  .card-header {{ padding: 10px 16px; background: rgba(255,255,255,.03);
                  display: flex; align-items: center; gap: 10px; font-size: .95rem; }}
  .card-body {{ padding: 12px 16px; }}
  .badge {{ border-radius: 4px; padding: 2px 8px; font-size: .75rem; font-weight: 700;
            white-space: nowrap; }}
  .info-table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  .info-table td {{ padding: 5px 10px; border-bottom: 1px solid var(--border);
                    vertical-align: top; }}
  .info-table td:first-child {{ width: 120px; color: var(--muted); font-weight: 600; }}
  .fix {{ color: #58c76b; }}
  code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px;
          font-family: 'Courier New', monospace; font-size: .85em; word-break: break-all; }}
  table.data-table {{ width: 100%; border-collapse: collapse; font-size: .85rem;
                      background: var(--surface); border-radius: var(--radius); overflow: hidden; }}
  table.data-table th {{ background: #21262d; padding: 8px 12px; text-align: left;
                          color: var(--muted); font-weight: 600; font-size: .8rem; }}
  table.data-table td {{ padding: 7px 12px; border-bottom: 1px solid var(--border); }}
  table.data-table tr:hover td {{ background: rgba(255,255,255,.02); }}
  .section {{ margin-bottom: 32px; }}
  .no-data {{ color: var(--muted); font-style: italic; padding: 12px; }}
  footer {{ margin-top: 48px; color: var(--muted); font-size: .8rem;
            border-top: 1px solid var(--border); padding-top: 16px; }}
  @media print {{ body {{ background: #fff; color: #000; }}
                  .card {{ break-inside: avoid; }} }}
</style>
</head>
<body>

<h1>🔍 GhostScan Security Report</h1>
<div class="meta">Target: <strong>{html_mod.escape(self.target)}</strong> &nbsp;|&nbsp;
Generated: {now} &nbsp;|&nbsp; GhostScan v2.0</div>

<h2>Executive Summary</h2>
<div class="summary">{summary_pills}</div>

<h2>Findings</h2>
<div class="section">
{"<div class='no-data'>No findings recorded.</div>" if not sorted_findings else finding_cards}
</div>

<h2>Reconnaissance</h2>
<div class="section">
  <h3>Open Ports</h3>
  {"<div class='no-data'>No port scan results.</div>" if not port_rows else f"""
  <table class="data-table">
    <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>"""}

  <h3>Subdomains ({len(self.results.get("recon",{}).get("subdomains",[]))} found)</h3>
  {"<div class='no-data'>No subdomains found.</div>" if not sub_rows else f"""
  <table class="data-table">
    <thead><tr><th>Subdomain</th><th>IPs</th><th>Source</th></tr></thead>
    <tbody>{sub_rows}</tbody>
  </table>"""}
</div>

<h2>Web Analysis</h2>
<div class="section">
  <h3>Directories / Files</h3>
  {"<div class='no-data'>No results.</div>" if not dir_rows else f"""
  <table class="data-table">
    <thead><tr><th>Status</th><th>Path</th><th>Size</th></tr></thead>
    <tbody>{dir_rows}</tbody>
  </table>"""}

  <h3>JavaScript Secrets</h3>
  {"<div class='no-data'>No secrets detected.</div>" if not js_rows else f"""
  <table class="data-table">
    <thead><tr><th>Type</th><th>File</th><th>Match</th></tr></thead>
    <tbody>{js_rows}</tbody>
  </table>"""}
</div>

<footer>
  Generated by <strong>GhostScan v2.0</strong> — Kali Linux Penetration Testing Framework<br>
  <em>For authorized security assessments only. Unauthorized use is illegal.</em>
</footer>
</body>
</html>"""

    # ── PDF ───────────────────────────────────────────────────────────────────

    def _write_pdf(self) -> str:
        path = self.output_dir / f"ghostscan_{self.safe_target}_{self.ts}.pdf"
        if not HAS_REPORTLAB:
            return str(path)

        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                 leftMargin=20*mm, rightMargin=20*mm,
                                 topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story = []

        # Cover
        story.append(Spacer(1, 30*mm))
        story.append(Paragraph("<font size=24 color='#1a6bbf'><b>GhostScan</b></font>", styles["Title"]))
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph("Security Assessment Report", styles["Heading2"]))
        story.append(Spacer(1, 8*mm))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"<b>Target:</b> {self.target}", styles["Normal"]))
        story.append(Paragraph(f"<b>Date:</b> {now}", styles["Normal"]))
        story.append(Paragraph(f"<b>Framework:</b> GhostScan v2.0 — Kali Linux", styles["Normal"]))
        story.append(PageBreak())

        # Summary table
        story.append(Paragraph("<b>Executive Summary</b>", styles["Heading1"]))
        story.append(Spacer(1, 4*mm))
        summary = self._severity_summary()
        sum_data = [["Severity", "Count"]]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = summary.get(sev, 0)
            if c:
                sum_data.append([sev, str(c)])
        if len(sum_data) > 1:
            t = Table(sum_data, colWidths=[80*mm, 40*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), rl_colors.HexColor("#1a6bbf")),
                ("TEXTCOLOR",  (0,0), (-1,0), rl_colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("GRID",       (0,0), (-1,-1), 0.5, rl_colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [rl_colors.HexColor("#f9f9f9"), rl_colors.white]),
            ]))
            story.append(t)
        story.append(Spacer(1, 8*mm))

        # Findings
        story.append(Paragraph("<b>Findings</b>", styles["Heading1"]))
        sorted_findings = sorted(self.all_findings,
                                  key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity","INFO")
            color = SEVERITY_COLORS_HEX.get(sev, "#666666")
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph(
                f'<font color="{color}"><b>[{i}] [{sev}]</b></font> {f.get("title","")}',
                styles["Heading3"]))
            rows = [["Field", "Value"]]
            for k, v in [("Category", f.get("category","")),
                         ("URL", f.get("url","")),
                         ("Detail", f.get("detail","")[:200]),
                         ("Evidence", f.get("evidence","")[:120]),
                         ("Remediation", f.get("remediation",""))]:
                if v:
                    rows.append([k, str(v)])
            if len(rows) > 1:
                t = Table(rows, colWidths=[40*mm, 130*mm])
                t.setStyle(TableStyle([
                    ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                    ("BACKGROUND", (0,0), (-1,0), rl_colors.HexColor("#eeeeee")),
                    ("GRID",       (0,0), (-1,-1), 0.3, rl_colors.HexColor("#cccccc")),
                    ("FONTSIZE",   (0,0), (-1,-1), 8),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ]))
                story.append(t)

        doc.build(story)
        return str(path)

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _collect_all_findings(self) -> list:
        all_f = []
        seen = set()
        for section in ["recon", "web", "vuln"]:
            for f in self.results.get(section, {}).get("findings", []):
                key = f"{f.get('severity')}{f.get('title')}{f.get('url')}"
                if key not in seen:
                    seen.add(key)
                    all_f.append(f)
        return all_f

    def _severity_summary(self) -> dict:
        counts = {}
        for f in self.all_findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _build_workflow_section(self) -> str:
        from modules.workflow import WorkflowEngine, WORKFLOW_STEPS
        try:
            engine = WorkflowEngine(self.config)
            recon_results = {
                "open_ports": self.results.get("recon", {}).get("open_ports", {}),
                "technologies": self.results.get("web", {}).get("technologies", {}),
                "subdomains": self.results.get("recon", {}).get("subdomains", []),
            }
            recommended = engine.get_contextual_steps(recon_results)
            lines = []
            seen_phases = set()
            for phase_key, step_id in recommended:
                phase_data = WORKFLOW_STEPS.get(phase_key, {})
                if phase_key not in seen_phases:
                    seen_phases.add(phase_key)
                    lines.append(f"\n### {phase_data.get('phase', phase_key)}")
                step = engine.get_step(phase_key, step_id)
                if step:
                    lines.append(f"\n#### [{step['id']}] {step['title']}")
                    lines.append(f"\nTools: `{'`, `'.join(step.get('tools', []))}`\n")
                    lines.append("```bash")
                    for cmd in step.get("kali_commands", []):
                        lines.append(engine.format_command(cmd))
                    lines.append("```")
            return "\n".join(lines) if lines else "_No workflow recommendations — run with --all for full analysis._"
        except Exception as e:
            return f"_Workflow generation error: {e}_"
