"""WebForge interactive REPL — combined class (Phase 10).

The command handlers live in ``webforg.apps.cli.commands`` and are combined
onto ``WebForgeREPL`` via mixins, keeping the dispatch table and bound-method
semantics identical to the pre-split ``webforg/cli.py``.
"""

from __future__ import annotations

import os
import shlex
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory

from webforg.apps.cli.completer import WebForgeCompleter
from webforg.apps.cli.commands import (
    HelpCommandsMixin,
    IntelCommandsMixin,
    ModuleCommandsMixin,
    ScannerCommandsMixin,
    SessionCommandsMixin,
    SocialCommandsMixin,
    WorkspaceCommandsMixin,
)
from webforg.apps.cli.console import STYLE, console
from webforg.core.module import BaseModule
from webforg.core.services import ModuleService, ScanService, TargetService
from webforg.core.theme import boot_sequence, error_msg
from webforg.core.workspace import Workspace


class WebForgeREPL(
    ModuleCommandsMixin,
    ScannerCommandsMixin,
    SessionCommandsMixin,
    WorkspaceCommandsMixin,
    IntelCommandsMixin,
    SocialCommandsMixin,
    HelpCommandsMixin,
):
    """Main interactive REPL."""

    def __init__(self):
        self.current_module: Optional[BaseModule] = None
        self.current_session_id: Optional[str] = None
        self.workspace: Workspace = Workspace("default")
        self.workspace.load()
        self._global_options: dict[str, str] = {}

        self.target_service = TargetService()
        self.module_service = ModuleService()
        self.scan_service = ScanService(
            modules=self.module_service,
            targets=self.target_service,
        )

        self.history = FileHistory(os.path.expanduser("~/.webforg_history"))
        self.completer = WebForgeCompleter(self)

        self.session = PromptSession(
            history=self.history,
            completer=self.completer,
            style=STYLE,
            complete_while_typing=True,
        )

        self.commands = {
            "use": self.cmd_use,
            "back": self.cmd_back,
            "show": self.cmd_show,
            "set": self.cmd_set,
            "setg": self.cmd_setg,
            "unset": self.cmd_unset,
            "get": self.cmd_get,
            "info": self.cmd_info,
            "search": self.cmd_search,
            "check": self.cmd_check,
            "exploit": self.cmd_exploit,
            "run": self.cmd_run,
            "sessions": self.cmd_sessions,
            "workspace": self.cmd_workspace,
            "fingerprint": self.cmd_fingerprint,
            "scan": self.cmd_scan,
            "bruteforce": self.cmd_bruteforce,
            "spray": self.cmd_spray,
            "enum": self.cmd_enum,
            "creds": self.cmd_creds,
            "social": self.cmd_social,
            "social_enum": self.cmd_social_enum,
            "social_reuse": self.cmd_social_reuse,
            "listener": self.cmd_listener,
            "save": self.cmd_save,
            "load": self.cmd_load,
            "export": self.cmd_export,
            "update": self.cmd_update,
            "exploits": self.cmd_exploits,
            "exploit-show": self.cmd_exploit_show,
            "shells": self.cmd_shells,
            "show-payload": self.cmd_show_payload,
            "cve-scan": self.cmd_cve_scan,
            "crawl": self.cmd_crawl,
            "auto-brute": self.cmd_auto_brute,
            "sploitus-exploit": self.cmd_sploitus_exploit,
            "secret-scan": self.cmd_secret_scan,
            "top10": self.cmd_top10,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
        }

    def get_prompt(self) -> str:
        parts = ["webforg"]
        if self.current_module:
            mod = self.current_module
            parts.append(f"({mod.name[:30]})")
        if self.current_session_id:
            parts.append(f"(session:{self.current_session_id})")
        return " > ".join(parts) + " > "

    def run(self):
        """Main REPL loop."""
        boot_sequence()

        while True:
            try:
                prompt = self.get_prompt()
                user_input = self.session.prompt(prompt, style=STYLE)

                if not user_input.strip():
                    continue

                # Handle in-session commands (when interacting with a shell)
                if self.current_session_id and not user_input.startswith(("sessions", "background", "exit", "quit")):
                    self._handle_session_command(user_input)
                    continue

                self._execute(user_input.strip())

            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted[/]")
                continue
            except EOFError:
                self.cmd_exit()
                break

    def _execute(self, line: str):
        """Parse and execute a command line."""
        parts = shlex.split(line)
        cmd_name = parts[0].lower()
        args = parts[1:]

        if cmd_name in self.commands:
            self.commands[cmd_name](args)
        else:
            error_msg(f"Unknown command: {cmd_name} — Type 'help' for available commands")

    def execute_command_string(self, cmd_string: str):
        """Execute semicolon-separated commands (-c mode)."""
        for cmd in cmd_string.split(";"):
            cmd = cmd.strip()
            if cmd:
                self._execute(cmd)

    @staticmethod
    def _normalize_url(raw: str) -> str:
        """Ensure a URL has a scheme. Bare domains get http:// prepended.

        Compatibility wrapper over TargetService.normalize_url.
        """
        return TargetService.normalize_url(raw)
