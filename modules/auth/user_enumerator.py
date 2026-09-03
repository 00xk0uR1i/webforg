"""
Social Media User/Email Enumerator
Checks if an email/username is registered on multiple platforms without logging in.
"""
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from webforg.core.module import BaseAuxiliaryModule, Option

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Checks if a username/email exists across multiple platforms without attempting login."""

    name = "Social Media User Enumerator"
    description = "Enumerates which platforms a username/email is registered on."
    author = "K0uR1i"
    rank = "normal"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("EMAIL", Option(str, required=False, description="Email to check"))
        self.add_option("USERNAME", Option(str, required=False, description="Username to check"))
        self.add_option("USER_FILE", Option(str, required=False, description="File with emails/usernames"))
        self.add_option("PLATFORMS", Option(str, required=False, default="all", description="all or comma-separated platforms"))
        self.add_option("MODE", Option(str, required=False, default="email", description="email | username"))

    def run(self) -> dict:
        mode = (self.get_option("MODE") or "email").lower()
        targets = []
        if self.get_option("EMAIL"):
            targets.append(self.get_option("EMAIL"))
        if self.get_option("USERNAME"):
            targets.append(self.get_option("USERNAME"))
        if self.get_option("USER_FILE"):
            try:
                with open(self.get_option("USER_FILE")) as f:
                    targets.extend([l.strip() for l in f if l.strip()])
            except FileNotFoundError:
                console.print(f"  [bold red]>[/] File not found: {self.get_option('USER_FILE')}")

        if not targets:
            return {"success": False, "error": "Provide EMAIL, USERNAME, or USER_FILE"}

        console.print()
        console.print(f"  [bold cyan]>[/] User Enumeration — checking [bold]{len(targets)}[/] target(s)")
        console.print()

        # Build platform check functions based on mode
        checks = {
            "instagram": self._check_instagram,
            "facebook": self._check_facebook,
            "twitter": self._check_twitter,
            "linkedin": self._check_linkedin,
            "tiktok": self._check_tiktok,
            "reddit": self._check_reddit,
            "github": self._check_github,
        }

        pf = (self.get_option("PLATFORMS") or "all").lower()
        if pf != "all":
            selected = [p.strip() for p in pf.split(",")]
            checks = {k: v for k, v in checks.items() if k in selected}

        all_results = {}
        for target in targets:
            console.print(f"  [bold green]>[/] Checking: [bold]{target}[/]")
            platform_results = {}
            for pname, check_fn in checks.items():
                try:
                    exists = check_fn(target)
                    status = "[bold green]FOUND [OK][/]" if exists else "[dim]NOT FOUND[/]"
                    platform_results[pname] = {"exists": exists}
                    console.print(f"    {pname:15s} {status}")
                except Exception as e:
                    platform_results[pname] = {"exists": "error", "error": str(e)[:60]}
                    console.print(f"    {pname:15s} [bold yellow]ERROR[/]")
                time.sleep(0.5)

            found_on = [p for p, r in platform_results.items() if r.get("exists") is True]
            console.print(f"  [bold]>[/] Found on {len(found_on)}/{len(checks)} platforms: {', '.join(found_on) if found_on else 'none'}")
            console.print()
            all_results[target] = platform_results

        # Summary
        table = Table(title="Enumeration Results", box=box.ROUNDED, border_style="bold cyan")
        table.add_column("Target", style="bold")
        for pname in checks:
            table.add_column(pname, width=12)

        for target, prs in all_results.items():
            row = [target]
            for pname in checks:
                r = prs.get(pname, {})
                if r.get("exists") is True:
                    row.append("[bold green]YES [OK][/]")
                elif r.get("exists") is False:
                    row.append("[dim]no[/]")
                else:
                    row.append("[dim]?[/]")
            table.add_row(*row)

        console.print(table)
        return {"success": True, "results": all_results}

    def _check_instagram(self, target: str) -> bool:
        import uuid
        try:
            resp = self.target.session.post(
                "https://i.instagram.com/api/v1/accounts/send_password_reset/",
                json={"user_email": target, "device_id": uuid.uuid4().hex},
                headers={"User-Agent": "Instagram 276.0.0.18.106 Android"},
                timeout=10,
            )
            data = resp.json()
            return "no users found" not in data.get("message", "").lower()
        except Exception:
            return None

    def _check_facebook(self, target: str) -> bool:
        try:
            resp = self.target.session.get(f"https://www.facebook.com/{target}", timeout=10, follow_redirects=True)
            return resp.status_code == 200 and "This content isn't available" not in resp.text
        except Exception:
            return None

    def _check_twitter(self, target: str) -> bool:
        try:
            resp = self.target.session.get(f"https://api.twitter.com/1.1/users/show.json?screen_name={target}", headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
            return resp.status_code == 200
        except Exception:
            return None

    def _check_linkedin(self, target: str) -> bool:
        try:
            resp = self.target.session.get(f"https://www.linkedin.com/in/{target}", timeout=10)
            return resp.status_code == 200 and "This profile doesn" not in resp.text
        except Exception:
            return None

    def _check_tiktok(self, target: str) -> bool:
        try:
            resp = self.target.session.get(f"https://www.tiktok.com/@{target}", timeout=10)
            return resp.status_code == 200 and "couldn't find this account" not in resp.text.lower()
        except Exception:
            return None

    def _check_reddit(self, target: str) -> bool:
        try:
            resp = self.target.session.get(f"https://www.reddit.com/user/{target}/about.json", timeout=10)
            return resp.status_code == 200
        except Exception:
            return None

    def _check_github(self, target: str) -> bool:
        try:
            resp = self.target.session.get(f"https://api.github.com/users/{target}", timeout=10)
            return resp.status_code == 200
        except Exception:
            return None
