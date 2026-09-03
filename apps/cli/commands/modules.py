"""Module-lifecycle commands (use/back/show/set/setg/unset/get/info/search/check/exploit/run).

Moved verbatim from ``webforg/cli.py`` (Phase 10).  These commands are the
REPL adapters over ``ModuleService``/``TargetService``/``ScanService``.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from webforg.apps.cli.console import console
from webforg.core.module import BaseAuxiliaryModule, BaseExploitModule
from webforg.core.theme import (
    MATRIX_GREEN,
    error_msg,
    info_msg,
    success_msg,
    themed_check,
    themed_exploit,
    themed_search_results,
    warning_msg,
)


class ModuleCommandsMixin:
    """Command handlers for selecting and driving modules."""

    def cmd_use(self, args: list[str]):
        if not args:
            console.print("[red]Usage: use <module_path>[/]")
            return
        path = args[0]
        mod = self.module_service.instantiate(path)
        if mod is None:
            error_msg(f"Module not found: {path}")
            return
        self.current_module = mod
        self.current_session_id = None
        # Apply global options to newly loaded module
        for name, value in self._global_options.items():
            if name in mod.options:
                try:
                    self.module_service.set_option(mod, name, value)
                except Exception:
                    pass
        console.print(f"  [bold green]>[/] Loaded module: [bold cyan]{mod}[/]")

    def cmd_back(self, args=None):
        if self.current_session_id:
            self.current_session_id = None
            warning_msg("Returned to module context")
        elif self.current_module:
            self.current_module = None
            warning_msg("Returned to root")

    def cmd_show(self, args: list[str]):
        if not args:
            console.print("[red]Usage: show modules|options|payloads|targets|advanced[/]")
            return

        sub = args[0].lower()

        if sub == "modules":
            modules = self.module_service.discover()
            table = Table(title="Loaded Exploit Modules", border_style=MATRIX_GREEN)
            table.add_column("Path", style="bold cyan")
            table.add_column("Name", style="green")
            table.add_column("Rank", style="yellow")
            table.add_column("CVE", style="red")

            for path, cls in sorted(modules.items()):
                # Quick instantiate to read metadata
                try:
                    inst = cls()
                    name = inst.name[:50]
                    rank = inst.rank.upper()
                    cve = getattr(inst, 'cve', '') or ''
                except Exception:
                    name = cls.__name__
                    rank = "?"
                    cve = ""
                table.add_row(path, name, rank, cve)

            console.print(table)

        elif sub == "options":
            if not self.current_module:
                error_msg("No module selected")
                return
            table = Table(title=f"Options for {self.current_module.name}", border_style=MATRIX_GREEN)
            table.add_column("Name", style="bold cyan")
            table.add_column("Current", style="green")
            table.add_column("Required", style="yellow")
            table.add_column("Type")
            table.add_column("Description")

            for name, opt in self.current_module.options.items():
                req = "[bold red]yes[/]" if opt.required else "no"
                val = str(opt.get()) if opt.get() is not None else "[dim]not set[/]"
                table.add_row(name, val, req, opt.type.__name__, opt.description)

            console.print(table)

        elif sub == "payloads" or sub == "payload":
            if sub == "payload" and len(args) > 1:
                self.cmd_show_payload(args[1])
                return
            from webforg.core.payload import list_payloads
            table = Table(title="Available Payloads", border_style=MATRIX_GREEN)
            table.add_column("Name", style="bold cyan")
            table.add_column("Description")
            for p in list_payloads():
                table.add_row(p, "(description)")
            console.print(table)

        elif sub == "targets":
            if not self.workspace.targets:
                warning_msg("No targets in workspace")
                return
            table = Table(title="Targets", border_style=MATRIX_GREEN)
            table.add_column("Host", style="bold cyan")
            table.add_column("Port")
            table.add_column("SSL")
            table.add_column("Path")
            for t in self.workspace.targets:
                table.add_row(t["host"], str(t["port"]), "[green][OK][/]" if t["ssl"] else "[red][FAIL][/]", t["path"])
            console.print(table)

    def cmd_set(self, args: list[str]):
        if not self.current_module:
            error_msg("No module selected")
            return
        if len(args) < 2:
            console.print("[red]Usage: set <OPTION> <value>[/]")
            return

        name, value = args[0].upper(), " ".join(args[1:])
        try:
            self.module_service.set_option(self.current_module, name, value)
            console.print(f"  [bold green]>[/] {name} => [bold]{value}[/]")
        except KeyError:
            error_msg(f"Unknown option: {name}")

    def cmd_setg(self, args: list[str]):
        """Set a global option (persists across module switches)."""
        if len(args) < 2:
            console.print("[red]Usage: setg <OPTION> <value>[/]")
            return
        name, value = args[0].upper(), " ".join(args[1:])
        self._global_options[name] = value
        if self.current_module and name in self.current_module.options:
            try:
                self.current_module.set_option(name, value)
            except KeyError:
                pass
        console.print(f"  [bold green]>[/] {name} => [bold]{value}[/] [dim](global)[/]")

    def cmd_unset(self, args: list[str]):
        if not self.current_module:
            error_msg("No module selected")
            return
        if not args:
            console.print("[red]Usage: unset <OPTION>[/]")
            return

        name = args[0].upper()
        try:
            self.module_service.set_option(self.current_module, name, None)
            console.print(f"  [bold green]>[/] {name} => [dim]unset[/]")
        except KeyError:
            error_msg(f"Unknown option: {name}")

    def cmd_get(self, args: list[str]):
        if not self.current_module:
            error_msg("No module selected")
            return
        if not args:
            console.print("[red]Usage: get <OPTION>[/]")
            return

        name = args[0].upper()
        try:
            val = self.module_service.get_option(self.current_module, name)
            console.print(f"  [bold cyan]>[/] {name} = [bold]{val}[/]")
        except KeyError:
            error_msg(f"Unknown option: {name}")

    def cmd_info(self, args=None):
        if not self.current_module:
            error_msg("No module selected")
            return

        mod = self.current_module

        info_lines = [
            f"[bold cyan]>[/] Module: [bold]{mod.name}[/]",
            f"[bold cyan]>[/] {mod.description}",
            f"[bold cyan]>[/] Author: [bold]{mod.author}[/]  Rank: [bold yellow]{mod.rank.upper()}[/]",
        ]

        if isinstance(mod, BaseExploitModule):
            info_lines += [
                f"[bold cyan]>[/] CVE: [bold red]{mod.cve or 'N/A'}[/]  CVSS: [bold yellow]{mod.cvss or 'N/A'}[/]",
                f"[bold cyan]>[/] Disclosed: {mod.disclosure_date or 'N/A'}",
            ]

        console.print(Panel("\n".join(info_lines), title="Module Info", border_style="bold green", padding=(1, 2)))

    def cmd_search(self, args: list[str]):
        query = " ".join(args).lower()
        results = self.module_service.search(query)

        if not results:
            warning_msg(f"No modules matching: {query}")
            return

        themed_search_results(query, len(results))
        table = Table(title=f"Modules matching '{query}'", border_style=MATRIX_GREEN)
        table.add_column("Path", style="bold cyan")
        table.add_column("Name", style="green")
        table.add_column("Rank", style="yellow")

        for path, cls in sorted(results):
            try:
                inst = cls()
                table.add_row(path, inst.name[:50], inst.rank.upper())
            except Exception:
                table.add_row(path, cls.__name__, "?")

        console.print(table)

    def cmd_check(self, args=None):
        if not isinstance(self.current_module, BaseExploitModule):
            error_msg("Module must be an exploit module to use 'check'")
            return

        errors = self.module_service.validate(self.current_module)
        if errors:
            for e in errors:
                error_msg(e)
            return

        themed_check(self.current_module.target.base_url)
        try:
            result = self.module_service.check(self.current_module)
            if result.vulnerable:
                console.print()
                console.print(f"  [bold green]╔══════════════════════════════════════════╗[/]")
                console.print(f"  [bold green]║  TARGET IS VULNERABLE!                   ║[/]")
                console.print(f"  [bold green]╚══════════════════════════════════════════╝[/]")
                console.print(f"  [dim green]>[/] {result.details}")
            else:
                console.print(f"  [bold yellow][-] Target is NOT vulnerable[/] — {result.details}")
        except Exception as e:
            error_msg(f"Check failed: {e}")

    def cmd_exploit(self, args=None):
        if not isinstance(self.current_module, BaseExploitModule):
            error_msg("Module must be an exploit module")
            return

        errors = self.module_service.validate(self.current_module)
        if errors:
            for e in errors:
                error_msg(e)
            return

        themed_exploit(self.current_module.target.base_url)
        try:
            result = self.module_service.exploit(self.current_module)
            if result.success:
                console.print()
                console.print(f"  [bold green]╔══════════════════════════════════════════╗[/]")
                console.print(f"  [bold green]║  EXPLOIT SUCCESSFUL                      ║[/]")
                console.print(f"  [bold green]╚══════════════════════════════════════════╝[/]")
                if result.output:
                    console.print(f"  [dim green]>[/] {result.output}")
                if result.session_id:
                    console.print(f"  [bold green]>[/] Session [bold cyan]{result.session_id}[/] established")
                    self.current_session_id = result.session_id
            else:
                error_msg(f"Exploit FAILED — {result.output}")
        except Exception as e:
            error_msg(f"Exploit error: {e}")

    def cmd_run(self, args=None):
        """Run the current module (exploit or auxiliary)."""
        if not self.current_module:
            error_msg("No module selected")
            return

        if isinstance(self.current_module, BaseExploitModule):
            self.cmd_exploit(args)
            return

        if isinstance(self.current_module, BaseAuxiliaryModule):
            errors = self.module_service.validate(self.current_module)
            if errors:
                for e in errors:
                    error_msg(e)
                return

            info_msg(f"Running {self.current_module.name}...")
            try:
                result = self.module_service.run(self.current_module)
                if result and result.get("success"):
                    success_msg(f"Module completed successfully")
                elif result:
                    warning_msg(f"Module finished with errors: {result.get('error', 'Unknown')}")
            except Exception as e:
                error_msg(f"Module error: {e}")
            return

        error_msg("Unknown module type")
