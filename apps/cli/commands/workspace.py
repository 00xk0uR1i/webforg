"""Workspace and persistence commands (workspace/fingerprint/save/load/export).

Moved verbatim from ``webforg/cli.py`` (Phase 10).  Workspace state lives in
``webforg.core.workspace``; the fingerprint handler keeps its historical inline
workspace-persistence behaviour unchanged.
"""

from __future__ import annotations

from rich.table import Table

from webforg.apps.cli.console import console
from webforg.core.theme import error_msg, success_msg, themed_fingerprint, warning_msg
from webforg.core.workspace import Workspace, list_workspaces


class WorkspaceCommandsMixin:
    """Command handlers for workspace + persistence workflows."""

    def cmd_workspace(self, args: list[str]):
        if not args:
            console.print(f"  [bold cyan]>[/] Workspace: [bold]{self.workspace.name}[/]")
            console.print(f"  [dim green]>[/] Targets: {len(self.workspace.targets)}")
            return

        sub = args[0].lower()

        if sub == "list":
            workspaces = list_workspaces()
            if not workspaces:
                warning_msg("No workspaces found")
                return
            for w in workspaces:
                marker = "[bold green]●[/]" if w == self.workspace.name else "[dim]○[/]"
                console.print(f"  {marker} {w}")

        elif sub == "add" and len(args) > 1:
            try:
                self.workspace = Workspace(args[1])
            except ValueError as e:
                error_msg(str(e))
                return
            self.workspace.load()
            success_msg(f"Switched to workspace: {args[1]}")

        elif sub == "select" and len(args) > 1:
            try:
                name = Workspace(args[1]).name
            except ValueError as e:
                error_msg(str(e))
                return
            if name in list_workspaces():
                self.workspace = Workspace(name)
                self.workspace.load()
                success_msg(f"Loaded workspace: {name}")
            else:
                error_msg(f"Workspace '{name}' not found")

    def cmd_fingerprint(self, args=None):
        if not self.current_module:
            error_msg("No module selected — target unknown")
            return

        target = self.current_module.target
        themed_fingerprint(target.base_url)

        try:
            fp = target.fingerprint()
            table = Table(title=f"Fingerprint: {target.base_url}")
            table.add_column("Attribute", style="cyan")
            table.add_column("Value")

            for key, val in fp.items():
                if key == "raw_headers":
                    continue
                if val:
                    if isinstance(val, list):
                        val = ", ".join(val)
                    table.add_row(key.replace("_", " ").title(), str(val))

            console.print(table)

            success_msg("Fingerprint saved to workspace")
            # Save to workspace
            existing = None
            for t in self.workspace.targets:
                if t["host"] == target.host:
                    existing = t
                    break

            if existing:
                existing["fingerprint"] = fp
            else:
                self.workspace.targets.append({
                    "host": target.host,
                    "port": target.port,
                    "ssl": target.ssl,
                    "path": target.path,
                    "fingerprint": fp,
                })

        except Exception as e:
            error_msg(f"Fingerprint failed: {e}")

    def cmd_save(self, args=None):
        self.workspace.save()
        success_msg(f"Workspace '{self.workspace.name}' saved")

    def cmd_load(self, args=None):
        self.workspace.load()
        success_msg(f"Workspace '{self.workspace.name}' loaded ({len(self.workspace.targets)} targets)")

    def cmd_export(self, args: list[str]):
        fmt = args[0].lower() if args else "json"

        if fmt == "json":
            import json
            data = {
                "workspace": self.workspace.name,
                "targets": self.workspace.targets,
                "results": self.workspace.results,
            }
            filename = f"webforg_export_{self.workspace.name}.json"
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            success_msg(f"Exported to {filename}")
