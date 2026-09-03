"""Tab completion for the WebForge CLI (extracted verbatim from webforg/cli.py)."""

from __future__ import annotations

from prompt_toolkit.completion import Completer, Completion

from webforg.core.workspace import list_workspaces


class WebForgeCompleter(Completer):
    """Tab completion for WebForge commands."""
    
    def __init__(self, repl: "WebForgeREPL"):
        self.repl = repl
        self._modules_cache: list[str] = []
    
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        
        # Build dynamic completions based on context
        words = text.split()
        
        if not words or (len(words) == 1 and not text.endswith(" ")):
            # Complete commands
            for cmd in self.repl.commands:
                if cmd.startswith(text.split()[0]) if words else cmd.startswith(text):
                    yield Completion(cmd, start_position=-len(text.split()[0]) if words else -len(text))
        
        elif words[0] == "use" and len(words) <= 2:
            # Complete module paths
            prefix = words[1] if len(words) > 1 else ""
            self._refresh_modules()
            for path in self._modules_cache:
                if prefix in path:
                    yield Completion(path, start_position=-len(prefix))
        
        elif words[0] in ("set", "setg", "unset") and len(words) == 2:
            # Complete option names
            if self.repl.current_module:
                for opt_name in self.repl.current_module.options:
                    if opt_name.startswith(words[1]):
                        yield Completion(opt_name, start_position=-len(words[1]))
        
        elif words[0] == "workspace" and len(words) == 2:
            # Complete workspace names
            for ws in list_workspaces():
                if ws.startswith(words[1]):
                    yield Completion(ws, start_position=-len(words[1]))
        
        elif words[0] == "sessions" and len(words) >= 2:
            # Session flags
            for flag in ["-l", "-i", "-k"]:
                if flag.startswith(words[1]):
                    yield Completion(flag, start_position=-len(words[1]))
    
    def _refresh_modules(self):
        if not self._modules_cache:
            modules = self.repl.module_service.discover()
            self._modules_cache = sorted(modules.keys())
