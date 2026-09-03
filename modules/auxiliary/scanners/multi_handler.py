"""Multi-handler auto-scan — runs ALL vulnerability checks against a target."""

from __future__ import annotations
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from webforg.core.module import BaseAuxiliaryModule, Option, discover_modules, instantiate_module
from webforg.core.target import Target
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich import box

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Automated multi-handler vulnerability scanner — runs all checks and generates a full report."""

    name = "Multi-Handler Auto Scanner"
    description = "Runs all generic exploit checks, header security, SSL, and technology fingerprinting against a target"
    author = "K0uR1i"
    rank = "excellent"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/", description="Base URI path"))
        self.add_option("THREADS", Option(int, required=False, default=5, description="Parallel threads for scanning"))
        self.add_option("CHECKS", Option(str, required=False, default="all", description="Checks to run: all,sqli,xss,lfi,ssti,ssrf,headers,ssl,tech"))
        self.add_option("PARAMS", Option(str, required=False, default="auto", description="Comma-separated params or 'auto'"))
        self.add_option("VERBOSE", Option(bool, required=False, default=True, description="Show detailed output"))

    def run(self) -> dict:
        url = self.target.base_url
        target_uri = self.get_option("TARGETURI") or "/"
        checks_filter = (self.get_option("CHECKS") or "all").lower()
        threads = self.get_option("THREADS") or 5

        console.print()
        console.print(f"  [bold green]>[/] Multi-Handler Auto Scan — [bold]{url}[/]")
        console.print(f"  [dim green]>[/] Checks: {checks_filter}  Threads: {threads}")
        console.print()

        all_results = []
        start_time = time.time()

        # ── Phase 1: Fingerprint ──
        if checks_filter in ("all", "tech"):
            console.print(f"  [bold cyan]>[/] Phase 1: Technology fingerprinting...")
            try:
                fp = self.target.fingerprint()
                fp_items = []
                for key, val in fp.items():
                    if key == "raw_headers":
                        continue
                    if val:
                        if isinstance(val, list):
                            val = ", ".join(val)
                        fp_items.append(f"  [bold cyan]>[/] {key.replace('_', ' ').title()}: [bold]{val}[/]")
                if fp_items:
                    console.print("\n".join(fp_items))
                console.print()
            except Exception as e:
                console.print(f"  [bold yellow]>[/] Fingerprint error: {e}")

        # ── Phase 2: Security Headers ──
        if checks_filter in ("all", "headers"):
            console.print(f"  [bold cyan]>[/] Phase 2: Security header analysis...")
            header_results = self._check_headers()
            all_results.extend(header_results)
            console.print()

        # ── Phase 3: SSL/TLS ──
        if checks_filter in ("all", "ssl"):
            console.print(f"  [bold cyan]>[/] Phase 3: SSL/TLS analysis...")
            ssl_results = self._check_ssl()
            all_results.extend(ssl_results)
            console.print()

        # ── Phase 4: Exploit module checks ──
        if checks_filter in ("all", "sqli", "xss", "lfi", "ssti", "ssrf"):
            console.print(f"  [bold cyan]>[/] Phase 4: Running exploit modules...")
            exploit_results = self._run_exploit_checks(checks_filter, target_uri, threads)
            all_results.extend(exploit_results)
            console.print()

        elapsed = time.time() - start_time
        vuln_count = sum(1 for r in all_results if r["status"] in ("VULN", "CRITICAL", "HIGH", "MEDIUM", "WARN"))

        # ── Results Table ──
        table = Table(
            title=f"Scan Results — {url}",
            box=box.ROUNDED,
            border_style="bold green",
        )
        table.add_column("Category", style="bold cyan", width=18)
        table.add_column("Check", style="white", width=30)
        table.add_column("Severity", width=10)
        table.add_column("Details", max_width=50)

        for r in all_results:
            sev = r["status"]
            if sev in ("CRITICAL", "VULN"):
                sev_style = f"[bold red]{sev}[/]"
            elif sev in ("HIGH",):
                sev_style = f"[red]{sev}[/]"
            elif sev in ("MEDIUM", "WARN"):
                sev_style = f"[yellow]{sev}[/]"
            elif sev in ("LOW", "INFO"):
                sev_style = f"[cyan]{sev}[/]"
            elif sev == "SAFE":
                sev_style = f"[green]PASS[/]"
            else:
                sev_style = f"[yellow]{sev}[/]"
            table.add_row(r["category"], r["check"], sev_style, r["details"][:50])

        console.print(table)

        # ── Summary Panel ──
        crit = sum(1 for r in all_results if r["status"] in ("CRITICAL", "VULN"))
        high = sum(1 for r in all_results if r["status"] == "HIGH")
        med = sum(1 for r in all_results if r["status"] in ("MEDIUM", "WARN"))
        low = sum(1 for r in all_results if r["status"] in ("LOW", "INFO"))
        safe = sum(1 for r in all_results if r["status"] == "SAFE")

        summary = (
            f"[bold red]Critical/Vuln: {crit}[/]  "
            f"[red]High: {high}[/]  "
            f"[yellow]Medium: {med}[/]  "
            f"[cyan]Low: {low}[/]  "
            f"[green]Pass: {safe}[/]  "
            f"[dim]Time: {elapsed:.1f}s[/]"
        )
        console.print(Panel(summary, title="Summary", border_style="bold green"))

        return {
            "success": True,
            "url": url,
            "results": all_results,
            "vuln_count": vuln_count,
            "elapsed": elapsed,
        }

    def _check_headers(self) -> list[dict]:
        """Check security headers."""
        results = []
        try:
            resp = self.target.session.get(self.target.base_url, timeout=10)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            checks = [
                ("Content-Security-Policy", "CSP Header", "MEDIUM", "Missing CSP allows XSS/injection attacks"),
                ("Strict-Transport-Security", "HSTS Header", "MEDIUM", "Missing HSTS allows downgrade attacks"),
                ("X-Frame-Options", "Clickjacking Protection", "LOW", "Missing X-Frame-Options allows clickjacking"),
                ("X-Content-Type-Options", "MIME Sniffing Protection", "LOW", "Missing X-Content-Type-Options allows MIME sniffing"),
                ("X-XSS-Protection", "XSS Filter", "LOW", "Missing X-XSS-Protection legacy XSS filter"),
                ("Referrer-Policy", "Referrer Policy", "INFO", "Missing Referrer-Policy leaks referrer info"),
                ("Permissions-Policy", "Permissions Policy", "INFO", "Missing Permissions-Policy"),
                ("Server", "Server Header", "INFO", f"Server header reveals: {headers.get('server', 'unknown')}"),
                ("X-Powered-By", "X-Powered-By Header", "INFO", f"X-Powered-By reveals: {headers.get('x-powered-by', 'unknown')}"),
            ]

            for header, name, severity, desc in checks:
                if header.lower() in headers:
                    val = headers[header.lower()]
                    if header in ("Server", "X-Powered-By"):
                        results.append({"category": "Headers", "check": name, "status": "WARN", "details": desc})
                    else:
                        results.append({"category": "Headers", "check": name, "status": "SAFE", "details": f"Present: {val[:30]}"})
                else:
                    if header in ("Server", "X-Powered-By"):
                        results.append({"category": "Headers", "check": name, "status": "SAFE", "details": "Not present (good)"})
                    else:
                        results.append({"category": "Headers", "check": name, "status": severity, "details": desc})

            # Cookie security
            for name, value in resp.cookies.items():
                cookie_obj = resp.cookies.jar._cookies.get(
                    (self.target.host, "/"), {}
                ).get(name)
                if cookie_obj:
                    if not getattr(cookie_obj, "secure", True):
                        results.append({"category": "Headers", "check": f"Cookie: {name}", "status": "MEDIUM", "details": "Missing Secure flag"})
                    if not getattr(cookie_obj, "has_nonstandard_attr", lambda k: False)("HttpOnly"):
                        # Fallback: check Set-Cookie header directly
                        set_cookie_headers = resp.headers.get_list("set-cookie")
                        for sc in set_cookie_headers:
                            if name in sc and "httponly" not in sc.lower():
                                results.append({"category": "Headers", "check": f"Cookie: {name}", "status": "LOW", "details": "Missing HttpOnly flag"})
                                break

        except Exception as e:
            results.append({"category": "Headers", "check": "Header Scan", "status": "ERROR", "details": str(e)[:50]})

        return results

    def _check_ssl(self) -> list[dict]:
        """Check SSL/TLS configuration."""
        results = []
        try:
            import ssl
            import socket
            from urllib.parse import urlparse

            parsed = urlparse(self.target.base_url)
            hostname = parsed.hostname
            port = parsed.port or (443 if self.target.ssl else 80)

            if not self.target.ssl:
                results.append({"category": "SSL/TLS", "check": "HTTPS Enabled", "status": "MEDIUM", "details": "Site does not use HTTPS"})
                return results

            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    results.append({"category": "SSL/TLS", "check": "SSL Connected", "status": "SAFE", "details": f"Protocol: {version}"})
                    results.append({"category": "SSL/TLS", "check": "Cipher Suite", "status": "SAFE", "details": cipher[0] if cipher else "unknown"})

                    # Check cert expiry
                    import datetime
                    not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.now(datetime.timezone.utc)
                    if not_after.tzinfo is None:
                        not_after = not_after.replace(tzinfo=datetime.timezone.utc)
                    days_left = (not_after - now).days
                    if days_left < 30:
                        results.append({"category": "SSL/TLS", "check": "Cert Expiry", "status": "HIGH", "details": f"Expires in {days_left} days!"})
                    elif days_left < 90:
                        results.append({"category": "SSL/TLS", "check": "Cert Expiry", "status": "WARN", "details": f"Expires in {days_left} days"})
                    else:
                        results.append({"category": "SSL/TLS", "check": "Cert Expiry", "status": "SAFE", "details": f"Valid for {days_left} days"})

                    # Check protocol version
                    if "TLSv1.3" not in version:
                        results.append({"category": "SSL/TLS", "check": "TLS Version", "status": "MEDIUM", "details": f"Not TLS 1.3: {version}"})

        except ssl.SSLCertVerificationError as e:
            results.append({"category": "SSL/TLS", "check": "SSL Verification", "status": "HIGH", "details": f"Cert error: {str(e)[:40]}"})
        except Exception as e:
            results.append({"category": "SSL/TLS", "check": "SSL Check", "status": "INFO", "details": f"Could not connect: {str(e)[:40]}"})

        return results

    def _run_exploit_checks(self, checks_filter: str, target_uri: str, threads: int) -> list[dict]:
        """Run exploit module checks in parallel."""
        results = []
        all_modules = discover_modules()
        generic_modules = {
            path: cls for path, cls in all_modules.items()
            if path.startswith("exploits/generic/")
        }

        # Filter modules
        if checks_filter != "all":
            filters = [f.strip() for f in checks_filter.split(",")]
            generic_modules = {
                path: cls for path, cls in generic_modules.items()
                if any(f in path for f in filters)
            }

        if not generic_modules:
            return results

        params_to_test = (self.get_option("PARAMS") or "auto").split(",") if self.get_option("PARAMS") else ["auto"]

        def run_check(module_info):
            path, cls = module_info
            try:
                mod = cls()
                mod.set_option("RHOSTS", self.get_option("RHOSTS"))
                mod.set_option("RPORT", self.get_option("RPORT"))
                mod.set_option("SSL", self.get_option("SSL"))
                mod.set_option("TARGETURI", target_uri)

                if "PARAM" in mod.options:
                    first_param = params_to_test[0] if params_to_test else "auto"
                    if first_param != "auto":
                        mod.set_option("PARAM", first_param)
                    else:
                        self._detect_params(mod)

                check_result = mod.check()
                status = "VULN" if check_result.vulnerable else "SAFE"
                return {
                    "category": "Exploit",
                    "check": mod.name,
                    "status": status,
                    "details": check_result.details,
                }
            except Exception as e:
                return {
                    "category": "Exploit",
                    "check": path,
                    "status": "ERROR",
                    "details": str(e)[:50],
                }

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
        ) as progress:
            task = progress.add_task("Running exploit checks", total=len(generic_modules))
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(run_check, item): item for item in generic_modules.items()}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                    except Exception as e:
                        result = {
                            "category": "Exploit",
                            "check": futures[future][0],
                            "status": "ERROR",
                            "details": str(e)[:50],
                        }
                    results.append(result)
                    progress.advance(task)

        return results

    def _detect_params(self, module):
        """Try common parameter names."""
        common_params = ["id", "page", "search", "q", "file", "path", "url", "cmd", "input", "name"]
        try:
            resp = self.target.session.get(self.target.base_url, timeout=10)
            import re
            form_params = re.findall(r'name=["\'](\w+)["\']', resp.text)
            link_params = re.findall(r'[?&](\w+)=', resp.text)
            all_params = list(dict.fromkeys(common_params + form_params + link_params))
            if all_params:
                if "PARAM" in module.options:
                    module.set_option("PARAM", all_params[0])
        except Exception:
            if "PARAM" in module.options:
                module.set_option("PARAM", "id")
