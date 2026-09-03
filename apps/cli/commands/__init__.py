"""CLI command handlers split out of ``webforg/cli.py`` (Phase 10).

Each module defines a mixin whose ``cmd_*`` methods are combined onto the
``WebForgeREPL`` class.  Method bodies were moved verbatim — no behavior
changes — so the dispatch table and bound-method semantics are preserved.
"""

from webforg.apps.cli.commands.help import HelpCommandsMixin
from webforg.apps.cli.commands.intel import IntelCommandsMixin
from webforg.apps.cli.commands.modules import ModuleCommandsMixin
from webforg.apps.cli.commands.scanners import ScannerCommandsMixin
from webforg.apps.cli.commands.sessions import SessionCommandsMixin
from webforg.apps.cli.commands.social import SocialCommandsMixin
from webforg.apps.cli.commands.workspace import WorkspaceCommandsMixin

__all__ = [
    "HelpCommandsMixin",
    "IntelCommandsMixin",
    "ModuleCommandsMixin",
    "ScannerCommandsMixin",
    "SessionCommandsMixin",
    "SocialCommandsMixin",
    "WorkspaceCommandsMixin",
]
