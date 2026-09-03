"""Shared Rich console + prompt-toolkit style for the WebForge CLI.

Extracted verbatim from ``webforg/cli.py`` (Phase 10) so command modules,
the completer and the REPL all share one console instance.
"""

from __future__ import annotations

from rich.console import Console
from prompt_toolkit.styles import Style


console = Console()

STYLE = Style.from_dict({
    "prompt": "bold green",
    "module-prompt": "bold cyan",
    "session-prompt": "bold yellow",
})
