"""Web fingerprinting auxiliary module."""

from webforg.core.module import BaseAuxiliaryModule
from webforg.core.target import Target
from rich.console import Console
from rich.table import Table

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Comprehensive web application fingerprinting."""
    
    name = "Web Fingerprinter"
    description = "Fingerprint web server, CMS, frameworks, and technologies"
    author = "webforg"
    rank = "normal"
    
    def run(self) -> dict:
        """Execute fingerprinting."""
        target = self.target
        
        console.print(f"[*] Fingerprinting {target.base_url}...")
        
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
            
            return {"success": True, "fingerprint": fp}
        
        except Exception as e:
            console.print(f"[red][!] Fingerprint failed: {e}[/]")
            return {"success": False, "error": str(e)}
