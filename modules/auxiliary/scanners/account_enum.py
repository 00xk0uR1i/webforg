"""Account enumeration module — discovers valid usernames via timing/error-based analysis."""

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
    """Account enumerator — discovers valid usernames via timing differences, error messages, and response analysis."""

    name = "Account Enumerator"
    description = "Enumerates valid usernames via timing analysis, error messages, and response differences"
    author = "K0uR1i"
    rank = "normal"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/login", description="Login form URL"))
        self.add_option("USERNAMES", Option(str, required=True, description="Username file path or comma-separated usernames"))
        self.add_option("USER_FIELD", Option(str, required=False, default=None, description="Username form field name"))
        self.add_option("PASS_FIELD", Option(str, required=False, default=None, description="Password form field name"))
        self.add_option("METHOD", Option(str, required=False, default="POST", description="HTTP method"))
        self.add_option("VALID_INDICATOR", Option(str, required=False, default=None, description="String that appears for valid usernames"))
        self.add_option("INVALID_INDICATOR", Option(str, required=False, default=None, description="String that appears for invalid usernames"))
        self.add_option("TRIES", Option(int, required=False, default=3, description="Number of tries per username for timing"))
        self.add_option("THRESHOLD", Option(float, required=False, default=0.3, description="Timing difference threshold (seconds)"))

    def run(self) -> dict:
        url = self.target.base_url + (self.get_option("TARGETURI") or "/login")
        session = self.target.session
        tries = self.get_option("TRIES") or 3
        threshold = self.get_option("THRESHOLD") or 0.3

        console.print()
        console.print(f"  [bold cyan]>[/] Account Enumerator — [bold]{url}[/]")
        console.print(f"  [dim green]>[/] Method: timing + error analysis  Tries/user: {tries}")

        # ── Load usernames ──
        usernames = self._load_usernames(self.get_option("USERNAMES"))
        if not usernames:
            return {"success": False, "error": "No usernames loaded"}
        console.print(f"  [dim green]>[/] Testing [bold]{len(usernames)}[/] usernames")
        console.print()

        # ── Detect fields ──
        user_field = self.get_option("USER_FIELD")
        pass_field = self.get_option("PASS_FIELD")
        if not user_field or not pass_field:
            user_field, pass_field = self._detect_fields(session, url)
            console.print(f"  [dim green]>[/] Fields: user=[bold]{user_field}[/]  pass=[bold]{pass_field}[/]")
        console.print()

        # ── Get baseline with invalid username ──
        console.print(f"  [dim green]>[/] Establishing baseline timing...")
        baseline_times = []
        for _ in range(tries):
            try:
                data = {user_field: "nonexistent_user_xyz_12345", pass_field: "test123"}
                start = time.time()
                if (self.get_option("METHOD") or "POST").upper() == "POST":
                    resp = session.post(url, data=data, timeout=10)
                else:
                    resp = session.get(url, params=data, timeout=10)
                elapsed = time.time() - start
                baseline_times.append(elapsed)
                resp_baseline = resp.text.lower()
                resp_baseline_status = resp.status_code
            except Exception:
                baseline_times.append(1.0)
                resp_baseline = ""
                resp_baseline_status = 200

        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 1.0
        console.print(f"  [dim green]>[/] Baseline: {avg_baseline:.3f}s avg, HTTP {resp_baseline_status}")
        console.print()

        # ── Enumerate ──
        valid_users = []
        invalid_users = []
        error_users = []
        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("•"),
            TextColumn("[bold]{task.fields[found]}[/]"),
        ) as progress:
            task = progress.add_task("Enumerating", total=len(usernames), found="0 found")

            for username in usernames:
                times = []
                resp_texts = []
                statuses = []
                success = False

                for _ in range(tries):
                    try:
                        data = {user_field: username, pass_field: "invalid_password_test"}
                        start = time.time()
                        if (self.get_option("METHOD") or "POST").upper() == "POST":
                            resp = session.post(url, data=data, timeout=10)
                        else:
                            resp = session.get(url, params=data, timeout=10)
                        elapsed = time.time() - start
                        times.append(elapsed)
                        resp_texts.append(resp.text.lower())
                        statuses.append(resp.status_code)

                        # Error message check
                        valid_ind = self.get_option("VALID_INDICATOR")
                        invalid_ind = self.get_option("INVALID_INDICATOR")
                        if valid_ind and valid_ind.lower() in resp.text.lower():
                            success = True
                            break
                        if invalid_ind and invalid_ind.lower() not in resp.text.lower():
                            success = True

                    except Exception:
                        times.append(0.0)
                        resp_texts.append("")
                        statuses.append(200)

                # ── Analysis ──
                avg_time = sum(times) / len(times) if times else 0.0
                time_diff = avg_time - avg_baseline

                # Check for differences
                is_valid = False
                reason = ""

                if success:
                    is_valid = True
                    reason = "Response indicator match"
                elif time_diff > threshold:
                    is_valid = True
                    reason = f"Slower by {time_diff:.3f}s (timing diff)"
                elif resp_texts and resp_texts[0] != resp_baseline:
                    if any(kw in resp_texts[0] for kw in ("welcome", "dashboard", "profile", "logout")):
                        is_valid = True
                        reason = "Different page content"

                status_str = "[bold green]VALID[/]" if is_valid else "[dim]INVALID[/]"
                if is_valid:
                    valid_users.append({"username": username, "reason": reason, "time_diff": time_diff})
                    found_count = len(valid_users)
                    progress.update(task, found=f"[bold green]{found_count} found[/]")
                else:
                    invalid_users.append(username)

                results.append({
                    "username": username,
                    "valid": is_valid,
                    "reason": reason,
                    "avg_time": avg_time,
                    "time_diff": time_diff,
                })

                progress.advance(task)

        # ── Results ──
        table = Table(title="Account Enumeration Results", box=box.ROUNDED, border_style="bold cyan")
        table.add_column("Username", style="bold cyan", width=25)
        table.add_column("Status", width=12)
        table.add_column("Avg Time", width=10)
        table.add_column("Diff", width=10)
        table.add_column("Reason")

        for r in results:
            status = "[bold green]VALID[/]" if r["valid"] else "[dim]INVALID[/]"
            diff = f"+{r['time_diff']:.3f}s" if r["time_diff"] > 0 else f"{r['time_diff']:.3f}s"
            diff_style = f"[bold yellow]{diff}[/]" if r["time_diff"] > threshold else f"[dim]{diff}[/]"
            table.add_row(
                r["username"],
                status,
                f"{r['avg_time']:.3f}s",
                diff_style,
                r["reason"],
            )

        console.print(table)

        summary = (
            f"[bold]Tested:[/] {len(usernames)}  "
            f"[bold green]Valid:[/] {len(valid_users)}  "
            f"[dim]Invalid:[/] {len(invalid_users)}  "
            f"[dim]Baseline:[/] {avg_baseline:.3f}s"
        )
        console.print(Panel(summary, border_style="bold cyan"))

        if valid_users:
            console.print(f"\n  [bold green][OK] Valid usernames found:[/]")
            for u in valid_users:
                console.print(f"    [bold cyan]→[/] [bold]{u['username']}[/]  [dim]({u['reason']})[/]")

        return {
            "success": True,
            "valid_users": valid_users,
            "total_tested": len(usernames),
            "results": results,
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
