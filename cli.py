"""Metasploit-style interactive REPL with Hollywood hacking theme.

Phase 10: the implementation was split into ``webforg.apps.cli`` (command
handlers, completer, console, REPL class).  This module stays as the public
entry point and re-exports the implementation so existing imports
(``webforg.main``, ``tests/cli/*``, tooling) keep working unchanged.
"""

from __future__ import annotations

from webforg.apps.cli import STYLE, WebForgeCompleter, WebForgeREPL, console

__all__ = [
    "WebForgeREPL",
    "WebForgeCompleter",
    "console",
    "STYLE",
]
