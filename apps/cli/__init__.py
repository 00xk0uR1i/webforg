"""WebForge CLI application package (Phase 10).

Implementation previously living in ``webforg/cli.py`` was split here:
command handlers live in ``webforg.apps.cli.commands``, the REPL class in
``webforg.apps.cli.repl``, and shared console/style in ``webforg.apps.cli.console``.
``webforg/cli.py`` remains a re-export wrapper for backwards compatibility.
"""

from __future__ import annotations

from webforg.apps.cli.completer import WebForgeCompleter
from webforg.apps.cli.console import STYLE, console
from webforg.apps.cli.repl import WebForgeREPL

__all__ = [
    "WebForgeREPL",
    "WebForgeCompleter",
    "console",
    "STYLE",
]
