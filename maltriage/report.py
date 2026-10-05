"""Render a :class:`TriageResult` to terminal, Markdown, HTML or JSON."""

from __future__ import annotations

import html
import json
from typing import List

from .models import TriageResult

# Verdict -> (rich style, hex colour) so terminal and HTML agree.
VERDICT_STYLE = {
    "CLEAN": ("bold green", "#2ecc71"),
    "LOW": ("bold green", "#27ae60"),
    "MEDIUM": ("bold yellow", "#f1c40f"),
    "HIGH": ("bold red", "#e67e22"),
    "CRITICAL": ("bold white on red", "#e74c3c"),
}

SEV_STYLE = {0: "dim", 1: "cyan", 2: "yellow", 3: "red"}


# --------------------------------------------------------------------------- #
# Terminal (rich)
# --------------------------------------------------------------------------- #
def render_terminal(result: TriageResult, min_severity: int = 0) -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    style, _ = VERDICT_STYLE.get(result.verdict, ("bold", ""))
    s = result.sample

    header = (
        f"[{style}]{result.verdict}[/]  (score {result.score:.1f}/10)\n"
        f"[bold]{s.name or '<unnamed>'}[/]  {s.type}\n"
        f"sha256: {s.sha256 or 'n/a'}"
    )
    if result.family:
        header += f"\nfamily: [bold magenta]{', '.join(result.family)}[/]"
    console.print(Panel(header, title="maltriage", border_style=style.split()[-1]))

    sigs = [x for x in result.signatures if x.severity >= min_severity]
    if sigs:
        t = Table(title=f"Signatures ({len(sigs)})", show_lines=False, expand=True)
        t.add_column("Sev", justify="center", width=4)
        t.add_column("Name", style="bold", no_wrap=True)
        t.add_column("Description")
        for sig in sigs:
            sev_style = SEV_STYLE.get(sig.severity, "white")
            t.add_row(f"[{sev_style}]{sig.severity}[/]", sig.name, sig.description[:80])
        console.print(t)

    if result.techniques:
        t = Table(title=f"MITRE ATT&CK ({len(result.techniques)})", expand=True)
        t.add_column("Technique", style="bold cyan", no_wrap=True)
        t.add_column("Name")
        for tech in result.techniques:
            t.add_row(tech.id, tech.name or "[dim]—[/]")
        console.print(t)

    _print_iocs_terminal(console, result)


def _print_iocs_terminal(console, result: TriageResult) -> None:
    from rich.table import Table

    iocs = result.iocs
    if iocs.is_empty():
        console.print("[dim]No network/host IOCs extracted.[/]")
        return
    t = Table(title=f"IOCs ({iocs.total()})", expand=True)
    t.add_column("Type", style="bold", width=14)
    t.add_column("Indicator")
    for dom in iocs.domains:
        t.add_row("domain", dom)
    for ip in iocs.ips:
        t.add_row("ip", ip)
    for url in iocs.urls:
        t.add_row("url", url)
    for drop in iocs.dropped:
        t.add_row("dropped", f"{drop.name}  [dim]{drop.sha256[:16]}[/]")
    for key in iocs.registry_keys[:20]:
        t.add_row("registry", key)
    for mutex in iocs.mutexes:
        t.add_row("mutex", mutex)
    console.print(t)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def render_markdown(result: TriageResult, min_severity: int = 0) -> str:
    s = result.sample
    lines: List[str] = []
    lines.append(f"# Malware Triage — `{s.name or 'sample'}`")
    lines.append("")
    lines.append(f"**Verdict:** `{result.verdict}`  ·  **Score:** {result.score:.1f}/10")
    if result.family:
        lines.append(f"**Family:** {', '.join(result.family)}")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Type | {s.type or 'n/a'} |")
    lines.append(f"| Size | {s.size} bytes |")
    lines.append(f"| MD5 | `{s.md5 or 'n/a'}` |")
    lines.append(f"| SHA1 | `{s.sha1 or 'n/a'}` |")
    lines.append(f"| SHA256 | `{s.sha256 or 'n/a'}` |")
    if result.analysis_id:
        lines.append(f"| Analysis ID | {result.analysis_id} |")
    lines.append("")

    sigs = [x for x in result.signatures if x.severity >= min_severity]
    if sigs:
        lines.append(f"## Signatures ({len(sigs)})")
        lines.append("")
        lines.append("| Sev | Name | Description |")
        lines.append("| --- | --- | --- |")
        for sig in sigs:
            desc = sig.description.replace("|", "\\|")
            lines.append(f"| {sig.severity} | `{sig.name}` | {desc} |")
        lines.append("")

    if result.techniques:
        lines.append(f"## MITRE ATT&CK ({len(result.techniques)})")
        lines.append("")
        for tech in result.techniques:
            lines.append(f"- [`{tech.id}`]({tech.url}) {tech.name}")
        lines.append("")

    iocs = result.iocs
    if not iocs.is_empty():
        lines.append(f"## IOCs ({iocs.total()})")
        lines.append("")
        for label, items in (
            ("Domains", iocs.domains),
            ("IPs", iocs.ips),
            ("URLs", iocs.urls),
            ("Registry keys", iocs.registry_keys),
            ("Mutexes", iocs.mutexes),
        ):
            if items:
                lines.append(f"**{label}**")
                lines.extend(f"- `{item}`" for item in items)
                lines.append("")
        if iocs.dropped:
            lines.append("**Dropped files**")
            for drop in iocs.dropped:
                lines.append(f"- `{drop.name}` ({drop.type}) `{drop.sha256}`")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by [maltriage](https://github.com/defamp/maltriage)._")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# JSON (machine-readable export)
# --------------------------------------------------------------------------- #
def render_json(result: TriageResult, iocs_only: bool = False) -> str:
    if iocs_only:
        payload = result.to_dict()["iocs"]
    else:
        payload = result.to_dict()
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------- #
# HTML (standalone, self-contained)
# --------------------------------------------------------------------------- #
def render_html(result: TriageResult, min_severity: int = 0) -> str:
    s = result.sample
    _, colour = VERDICT_STYLE.get(result.verdict, ("", "#555"))
    esc = html.escape

    def rows(items):
        return "".join(f"<li><code>{esc(str(i))}</code></li>" for i in items)

    sig_rows = "".join(
        f"<tr><td class='sev sev{min(sig.severity,3)}'>{sig.severity}</td>"
        f"<td><code>{esc(sig.name)}</code></td><td>{esc(sig.description)}</td></tr>"
        for sig in result.signatures
        if sig.severity >= min_severity
    )
    ttp_rows = "".join(
        f"<tr><td><a href='{t.url}' target='_blank'><code>{esc(t.id)}</code></a></td>"
        f"<td>{esc(t.name)}</td></tr>"
        for t in result.techniques
    )
    dropped = "".join(
        f"<li><code>{esc(d.name)}</code> <span class='dim'>{esc(d.type)} {esc(d.sha256[:32])}</span></li>"
        for d in result.iocs.dropped
    )
    family = f"<span class='fam'>{esc(', '.join(result.family))}</span>" if result.family else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>maltriage — {esc(s.name or 'sample')}</title>
<style>
  :root {{ --bg:#0f1115; --card:#191c23; --fg:#e6e6e6; --dim:#8a8f99; --accent:{colour}; --line:#262b35; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--fg); }}
  .wrap {{ max-width:900px; margin:0 auto; padding:24px 16px; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .verdict {{ display:inline-block; padding:4px 14px; border-radius:6px; font-weight:700; background:var(--accent); color:#111; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px 18px; margin:16px 0; }}
  table {{ width:100%; border-collapse:collapse; }}
  th,td {{ text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
  th {{ color:var(--dim); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  code {{ background:#0c0e12; padding:1px 5px; border-radius:4px; font-size:13px; }}
  .sev {{ text-align:center; font-weight:700; width:40px; }}
  .sev1 {{ color:#5dade2; }} .sev2 {{ color:#f1c40f; }} .sev3 {{ color:#e74c3c; }}
  .dim,.fam {{ color:var(--dim); font-size:13px; }}
  .fam {{ color:#c39bd3; }}
  ul {{ margin:6px 0; padding-left:18px; }} li {{ margin:2px 0; }}
  .meta td:first-child {{ color:var(--dim); width:120px; }}
  footer {{ color:var(--dim); font-size:12px; margin-top:24px; }}
</style></head>
<body><div class="wrap">
  <h1>🧬 {esc(s.name or 'sample')}</h1>
  <p><span class="verdict">{esc(result.verdict)}</span> &nbsp; score {result.score:.1f}/10 &nbsp; {family}</p>
  <div class="card"><table class="meta">
    <tr><td>Type</td><td>{esc(s.type or 'n/a')}</td></tr>
    <tr><td>Size</td><td>{s.size} bytes</td></tr>
    <tr><td>MD5</td><td><code>{esc(s.md5 or 'n/a')}</code></td></tr>
    <tr><td>SHA256</td><td><code>{esc(s.sha256 or 'n/a')}</code></td></tr>
    {f'<tr><td>Analysis ID</td><td>{esc(result.analysis_id)}</td></tr>' if result.analysis_id else ''}
  </table></div>
  {f'<div class="card"><h3>Signatures</h3><table><tr><th>Sev</th><th>Name</th><th>Description</th></tr>{sig_rows}</table></div>' if sig_rows else ''}
  {f'<div class="card"><h3>MITRE ATT&CK</h3><table><tr><th>Technique</th><th>Name</th></tr>{ttp_rows}</table></div>' if ttp_rows else ''}
  <div class="card"><h3>IOCs ({result.iocs.total()})</h3>
    {f'<h4>Domains</h4><ul>{rows(result.iocs.domains)}</ul>' if result.iocs.domains else ''}
    {f'<h4>IPs</h4><ul>{rows(result.iocs.ips)}</ul>' if result.iocs.ips else ''}
    {f'<h4>URLs</h4><ul>{rows(result.iocs.urls)}</ul>' if result.iocs.urls else ''}
    {f'<h4>Dropped files</h4><ul>{dropped}</ul>' if dropped else ''}
    {f'<h4>Registry keys</h4><ul>{rows(result.iocs.registry_keys)}</ul>' if result.iocs.registry_keys else ''}
    {f'<h4>Mutexes</h4><ul>{rows(result.iocs.mutexes)}</ul>' if result.iocs.mutexes else ''}
  </div>
  <footer>Generated by maltriage · offline, no API keys.</footer>
</div></body></html>"""
