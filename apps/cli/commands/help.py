"""Help and exit commands (help/exit).

Moved verbatim from ``webforg/cli.py`` (Phase 10).
"""

from __future__ import annotations

import sys

from rich import box
from rich.table import Table

from webforg.apps.cli.console import console
from webforg.core.session import sessions
from webforg.core.theme import DIM_GREEN, MATRIX_GREEN, glitch_text, scanline_effect, typewrite


class HelpCommandsMixin:
    """Command handlers for help and exiting the REPL."""

    def cmd_help(self, args=None):
        """Show help."""
        table = Table(title="WebForge Command Reference", border_style=MATRIX_GREEN, box=box.ROUNDED)
        table.add_column("Command", style="bold cyan", min_width=40)
        table.add_column("Description", style="green")

        # Quick attack commands
        table.add_row("─── QUICK ATTACK COMMANDS ───", "")
        table.add_row("scan <url> [checks]", "Auto-scan generic vulns (sqli,xss,lfi,ssti,ssrf,headers,ssl,tech)")
        table.add_row("cve-scan <url> [mode] [user] [pass]", "Scan ALL known CVEs against target (smart=all)")
        table.add_row("secret-scan <url> [depth]", "Find passwords, keys, hashes, emails, hidden files & secrets")
        table.add_row("sploitus-exploit <url> [type] [args]", "Run Sploitus exploits against target (auto/cve/tech/cms)")
        table.add_row("crawl <url> [depth]", "Crawl target for login forms (discover CSRF, hidden fields, etc.)")
        table.add_row("auto-brute <url> <creds_file> [depth]", "Auto-brute: crawl for forms then brute force with user:pass combos")
        table.add_row("bruteforce <url> <users> [wordlist]", "Brute force login form — thread-based password guessing")
        table.add_row("spray <url> <users> [passwords]", "Password spray — low-and-slow to avoid account lockout")
        table.add_row("enum <url> <usernames>", "Enumerate valid usernames via timing/error differential")
        table.add_row("creds <url> <user:pass file>", "Credential stuffing — test leaked username:password pairs")

        table.add_row("", "")

        # Social media auth
        table.add_row("─── SOCIAL MEDIA AUTH ───", "")
        table.add_row("social <platform> <email> <pass>", "Test creds on platform (instagram,facebook,twitter,linkedin,tiktok,reddit,discord,github,google)")
        table.add_row("social_enum <email|username>", "Discover which platforms a user/email is registered on")
        table.add_row("social_reuse <email> <pass>", "Credential reuse test — same email:pass across ALL platforms")

        table.add_row("", "")

        # Module commands
        table.add_row("─── MODULE COMMANDS ───", "")
        table.add_row("use <path>", "Select a module (e.g. use exploits/cve/2025/CVE-2025-8110_gogs_rce)")
        table.add_row("back", "Deselect current module / exit session")
        table.add_row("show modules|options|payloads|targets", "List modules / options / payloads / saved targets")
        table.add_row("set <OPTION> <value>", "Set option on current module")
        table.add_row("setg <OPTION> <value>", "Set global option (persists across modules)")
        table.add_row("unset <OPTION>", "Clear a module option")
        table.add_row("get <OPTION>", "Read current value of an option")
        table.add_row("info", "Show full details for selected module")
        table.add_row("search <query>", "Search modules by name, CVE, or keyword")
        table.add_row("check", "Check if target is vulnerable (non-intrusive)")
        table.add_row("run / exploit", "Launch the exploit or run auxiliary module")

        table.add_row("", "")

        # Sessions & listeners
        table.add_row("─── SESSIONS & LISTENERS ───", "")
        table.add_row("sessions [-l|-i|-k|-u|-p|-cv|-ce]", "List / interact / kill / upgrade / probe / CVE-scan / exploit sessions")
        table.add_row("listener start --lhost IP --lport PORT", "Start a reverse shell listener")
        table.add_row("listener stop [name]", "Stop one or all listeners")
        table.add_row("listener list", "Show all active listeners")

        table.add_row("", "")

        # Info & database
        table.add_row("─── INFO & DATABASE ───", "")
        table.add_row("workspace [list|add|select]", "Manage pentest workspaces")
        table.add_row("fingerprint", "Full technology fingerprint of target")
        table.add_row("shells", "List all 19 reverse shell payloads (bash, python, php, java, etc.)")
        table.add_row("show-payload <name>", "Show source code for a specific shell payload")
        table.add_row("exploits [query]", "Search Sploitus exploit DB / show stats")
        table.add_row("exploit-show <query>", "Display full exploit source from Sploitus")
        table.add_row("top10 [rank|search]", "OWASP Top 10 web vuln reference + exploitation guides")
        table.add_row("update [--sploitus-pages=N]", "Sync CVE database from NVD + CISA KEV + Sploitus")
        table.add_row("save / load", "Persist / restore workspace state")
        table.add_row("export <json|html>", "Export scan results")
        table.add_row("help", "Show this help")
        table.add_row("exit / quit", "Exit WebForge (kills sessions, saves workspace)")
        table.add_row("show-payload <name>", "Show code for a specific shell payload")
        table.add_row("exploits [query]", "Search sploitus exploits / show stats")
        table.add_row("exploit-show <query>", "Show full exploit source code")
        table.add_row("top10 [rank|search]", "OWASP Top 10 web vuln guides + payloads")
        table.add_row("help", "Show this help")
        table.add_row("exit / quit", "Exit WebForge")

        console.print()
        console.print(table)
        console.print()

    def cmd_exit(self, args=None):
        self.workspace.save()
        sessions.kill_all()
        console.print()
        scanline_effect(width=50, lines=1)
        typewrite("  Session terminated. Disconnecting...", delay=0.03, color=DIM_GREEN)
        typewrite("  All sessions killed. Workspace saved.", delay=0.02, color=DIM_GREEN)
        console.print()
        glitch_text("  Goodbye. Stay dangerous.", iterations=3, delay=0.05)
        console.print()
        scanline_effect(width=50, lines=2)
        console.print()
        sys.exit(0)
