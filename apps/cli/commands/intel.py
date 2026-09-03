"""Intel / reference commands (exploits/exploit-show/top10/update/shells/show-payload).

Moved verbatim from ``webforg/cli.py`` (Phase 10).  These are read-only REPL
adapters over the intelligence helpers (``cve_db``, ``shellgen``, ``top10``).
"""

from __future__ import annotations

from rich import box
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from webforg.apps.cli.console import console
from webforg.core.theme import (
    MATRIX_GREEN,
    error_msg,
    glitch_text,
    themed_search_results,
    warning_msg,
)


class IntelCommandsMixin:
    """Command handlers for intel database + payload reference tools."""

    def cmd_exploits(self, args: list[str]):
        """Search sploitus exploits."""
        from webforg.core.cve_db import search_sploitus_exploits, get_sploitus_stats

        if not args:
            stats = get_sploitus_stats()
            table = Table(title="Sploitus Exploit Database", border_style=MATRIX_GREEN)
            table.add_column("Metric", style="bold cyan")
            table.add_column("Value", style="green")
            table.add_row("Total exploits", str(stats["total_exploits"]))
            table.add_row("Unique CVEs", str(stats["unique_cves"]))
            table.add_row("Last fetch", stats["last_fetch"] or "Never")
            for t, count in stats.get("by_type", {}).items():
                table.add_row(f"  {t}", str(count))
            console.print(table)
            return

        query = " ".join(args)
        themed_search_results(query, 0)
        results = search_sploitus_exploits(query=query)

        if not results:
            warning_msg(f"No exploits matching: {query}")
            return

        table = Table(title=f"Sploitus Exploits: '{query}'", border_style=MATRIX_GREEN)
        table.add_column("CVE", style="bold red")
        table.add_column("Title", style="cyan", max_width=50)
        table.add_column("CVSS", style="yellow")
        table.add_column("Type")
        table.add_column("URL")

        for r in results[:30]:
            cve = r.get("cve_id") or "-"
            title = (r.get("title") or "")[:50]
            cvss = str(r.get("cvss") or "-")
            etype = r.get("type") or "-"
            url = (r.get("source_url") or "")[:40]
            table.add_row(cve, title, cvss, etype, url)

        console.print(table)

    def cmd_exploit_show(self, args: list[str]):
        """Show full exploit source code from sploitus."""
        from webforg.core.cve_db import search_sploitus_exploits

        if not args:
            console.print("[red]Usage: exploit-show <query>[/]")
            return

        query = " ".join(args)
        themed_search_results(query, 0)
        results = search_sploitus_exploits(query=query, limit=1)

        if not results:
            warning_msg(f"No exploit found for: {query}")
            return

        r = results[0]
        console.print(Panel(
            f"[bold]Title:[/] {r['title']}\n"
            f"[bold]CVE:[/] {r.get('cve_id') or 'N/A'}\n"
            f"[bold]CVSS:[/] {r.get('cvss') or 'N/A'}\n"
            f"[bold]Type:[/] {r.get('type') or 'N/A'}\n"
            f"[bold]URL:[/] {r.get('source_url') or 'N/A'}\n"
            f"[bold]Description:[/]\n{(r.get('description') or '')[:500]}",
            title="Exploit Info",
            border_style="bold green",
        ))

        code = r.get("code")
        if code:
            console.print(Syntax(code[:5000], "python", theme="monokai"))
        else:
            warning_msg("No source code available")

    def cmd_top10(self, args: list[str]):
        """Show OWASP Top 10 Web Vulnerabilities with full exploitation guides."""
        from webforg.core.top10 import get_top10, get_top10_by_rank, search_top10

        if not args:
            vulns = get_top10()
            table = Table(title="OWASP Top 10 Web Vulnerabilities (2021)", border_style=MATRIX_GREEN)
            table.add_column("#", style="bold", width=3)
            table.add_column("ID", style="bold cyan", width=12)
            table.add_column("Name", style="white", width=38)
            table.add_column("Severity", width=10)
            table.add_column("CVSS", style="yellow", width=10)

            sev_colors = {
                "CRITICAL": "[bold red]CRITICAL[/]",
                "HIGH": "[red]HIGH[/]",
                "MEDIUM": "[yellow]MEDIUM[/]",
            }

            for v in vulns:
                table.add_row(
                    str(v.rank),
                    v.owasp_id,
                    v.name,
                    sev_colors.get(v.severity, v.severity),
                    v.cvss_range,
                )

            console.print(table)
            console.print("\n[dim]Use: top10 <rank> or top10 <search> for full details[/]")
            return

        query = args[0]

        try:
            rank = int(query)
            vuln = get_top10_by_rank(rank)
            if vuln:
                vulns = [vuln]
            else:
                vulns = []
        except ValueError:
            vulns = search_top10(query)

        if not vulns:
            warning_msg(f"No Top 10 entry matching: {query}")
            return

        for v in vulns:
            info_text = (
                f"[bold cyan]A{v.rank:02d}: {v.name}[/]\n"
                f"[bold]OWASP ID:[/] {v.owasp_id}  "
                f"[bold]Severity:[/] {v.severity}  "
                f"[bold]CVSS:[/] {v.cvss_range}\n\n"
                f"[bold]Description:[/]\n{v.description}\n\n"
                f"[bold]How It Works:[/]\n{v.how_it_works}\n\n"
                f"[bold]Impact:[/]\n{v.impact}\n\n"
                f"[bold]Remediation:[/]"
            )
            for r in v.remediation:
                info_text += f"\n  [green][OK][/] {r}"

            if v.real_world_cves:
                info_text += f"\n\n[bold]Real-World CVEs:[/]"
                for cve in v.real_world_cves:
                    info_text += f"\n  [red]●[/] {cve}"

            if v.tools:
                info_text += f"\n\n[bold]Tools:[/] {', '.join(v.tools)}"

            console.print(Panel(info_text, border_style="cyan", padding=(1, 2)))

            if v.techniques:
                console.print(f"\n[bold]Exploitation Techniques:[/]\n")
                for i, tech in enumerate(v.techniques, 1):
                    tech_text = (
                        f"[bold yellow]{i}. {tech.name}[/]\n"
                        f"{tech.description}\n"
                    )
                    if tech.payloads:
                        tech_text += f"\n[bold]Payloads:[/]\n"
                        for p in tech.payloads:
                            tech_text += f"  [red]→[/] [monokai]{p}[/]\n"
                    if tech.detection_patterns:
                        tech_text += f"\n[bold]Detection:[/] {', '.join(tech.detection_patterns[:3])}"
                    if tech.tools:
                        tech_text += f"\n[bold]Tools:[/] {', '.join(tech.tools)}"
                    if tech.references:
                        tech_text += f"\n[bold]References:[/] {tech.references[0]}"

                    console.print(Panel(tech_text, border_style="yellow", padding=(0, 1)))

            if v.references:
                console.print(f"\n[bold]References:[/]")
                for ref in v.references:
                    console.print(f"  [dim]•[/] {ref}")

            console.print()

    def cmd_update(self, args=None):
        from webforg.core.cve_db import update_cve_database

        sploitus_pages = 5
        nvd_days = 90

        for arg in args:
            if arg.startswith("--sploitus-pages="):
                sploitus_pages = int(arg.split("=", 1)[1])
            elif arg.startswith("--nvd-days="):
                nvd_days = int(arg.split("=", 1)[1])
            elif arg == "--sploitus-only":
                nvd_days = 0

        console.print()
        glitch_text("  >> DATABASE UPDATE INITIATED", iterations=4, delay=0.03)
        console.print(f"  [dim green]>[/] Sources: NVD ({nvd_days}d), CISA KEV, Sploitus ({sploitus_pages} pages)")
        console.print()
        update_cve_database(nvd_days=nvd_days, sploitus_pages=sploitus_pages)

    def cmd_shells(self, args=None):
        """List available reverse shell payloads."""
        from webforg.core.shellgen import ShellGenerator
        gen = ShellGenerator()
        shells = gen.generate_all()

        table = Table(title="Reverse Shell Payloads", border_style=MATRIX_GREEN, box=box.ROUNDED)
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Name", style="bold")
        table.add_column("Language", style="green")
        table.add_column("OS", style="yellow")
        table.add_column("Description")

        for i, s in enumerate(shells, 1):
            table.add_row(str(i), s.name, s.language, s.os, s.description)

        console.print(table)
        console.print(f"\n  Use: [bold]set PAYLOAD <name>[/] or [bold]show payload <name>[/] to view code")

    def cmd_show_payload(self, name: str):
        """Show a specific shell payload's code."""
        from webforg.core.shellgen import ShellGenerator
        gen = ShellGenerator()
        for s in gen.generate_all():
            if s.name.lower() == name.lower() or s.language.lower() == name.lower():
                console.print(f"\n  [bold cyan]{s.name}[/] ({s.language} / {s.os})")
                console.print(f"  {s.description}\n")
                console.print(f"  [dim]{s.cmd}[/]\n")
                return
        error_msg(f"Payload '{name}' not found. Use 'shells' to list available payloads.")
