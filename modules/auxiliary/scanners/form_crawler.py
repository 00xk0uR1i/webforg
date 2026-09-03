"""
Form Crawler — discovers all login/auth forms on a target site.
Crawls linked pages, detects forms with password fields, extracts
action URLs, field names, hidden fields, CSRF tokens, and cookies.

Usage (module):
    use auxiliary/scanners/form_crawler
    set RHOSTS target.com
    run

Usage (CLI):
    crawl target.com
"""
from __future__ import annotations
import time
from webforg.core.module import BaseAuxiliaryModule, Option
from webforg.engine.crawler import (
    COMMON_LOGIN_PATHS,
    LoginForm,
    extract_forms,
    extract_links,
    is_same_domain,
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Crawls target site to discover all login and authentication forms."""

    name = "Form Crawler"
    description = "Crawls a website to find login forms, extract CSRF tokens, field names, and action URLs"
    author = "webforg"
    rank = "good"

    # Common login-related paths to check
    COMMON_LOGIN_PATHS = COMMON_LOGIN_PATHS

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("TARGETURI", Option(str, required=False, default="/", description="Starting path"))
        self.add_option("TIMEOUT", Option(int, required=False, default=10, description="HTTP timeout"))
        self.add_option("DEPTH", Option(int, required=False, default=2, description="Crawl depth (links to follow)"))
        self.add_option("MAX_PAGES", Option(int, required=False, default=50, description="Max pages to crawl"))
        self.add_option("FOLLOW_LINKS", Option(bool, required=False, default=True, description="Follow links on pages"))
        self.add_option("CHECK_COMMON", Option(bool, required=False, default=True, description="Also check common login paths"))

    def run(self) -> dict:
        base_url = self.target.base_url
        timeout = self.get_option("TIMEOUT") or 10
        depth = self.get_option("DEPTH") or 2
        max_pages = self.get_option("MAX_PAGES") or 50
        follow_links = self.get_option("FOLLOW_LINKS") or True
        check_common = self.get_option("CHECK_COMMON") or True

        console.print()
        console.print(f"  [bold cyan]>[/] Form Crawler — [bold]{base_url}[/]")
        console.print(f"  [dim green]>[/] Depth: {depth}  Max pages: {max_pages}  Common paths: {check_common}")
        console.print()

        visited = set()
        forms_found = []
        start_time = time.time()

        def crawl_page(url: str, current_depth: int):
            if len(visited) >= max_pages:
                return
            if url in visited:
                return
            if current_depth > depth:
                return

            visited.add(url)

            try:
                resp = self.target.session.get(url, timeout=timeout)
            except Exception:
                return

            # Extract forms from this page
            page_forms = self._extract_forms(url, resp)
            for form in page_forms:
                forms_found.append(form)
                console.print(f"  [bold green][+][/] Form found: {form.method} {form.action_url}")
                console.print(f"    [dim]user=[/]{form.user_field} [dim]pass=[/]{form.pass_field} [dim]csrf=[/]{form.csrf_field or 'none'} [dim]hidden=[/]{len(form.hidden_fields)}")

            # Follow links for deeper crawling
            if follow_links and current_depth < depth:
                links = self._extract_links(url, resp.text)
                for link in links:
                    if self._is_same_domain(link) and link not in visited:
                        crawl_page(link, current_depth + 1)

        # Phase 1: Crawl from starting path
        start_path = (self.get_option("TARGETURI") or "/").rstrip("/")
        start_url = f"{base_url}{start_path}"
        console.print(f"  [bold cyan]>[/] Phase 1: Crawling from {start_url}...")
        crawl_page(start_url, 0)

        # Phase 2: Check common login paths
        if check_common:
            console.print(f"  [bold cyan]>[/] Phase 2: Checking {len(self.COMMON_LOGIN_PATHS)} common login paths...")
            for path in self.COMMON_LOGIN_PATHS:
                if len(visited) >= max_pages:
                    break
                url = f"{base_url}{path}"
                if url not in visited:
                    crawl_page(url, 0)

        elapsed = time.time() - start_time

        # Deduplicate forms by action_url + user_field
        seen = set()
        unique_forms = []
        for f in forms_found:
            key = (f.action_url, f.user_field, f.pass_field)
            if key not in seen:
                seen.add(key)
                unique_forms.append(f)

        # Results
        console.print()
        table = Table(title=f"Detected Login Forms — {base_url}", box=box.ROUNDED, border_style="bold green")
        table.add_column("#", style="bold cyan", width=3)
        table.add_column("Action URL", style="bold", max_width=45)
        table.add_column("Method", width=6)
        table.add_column("User Field", style="yellow")
        table.add_column("Pass Field", style="yellow")
        table.add_column("CSRF", style="green")
        table.add_column("Hidden", width=6)

        for i, f in enumerate(unique_forms, 1):
            table.add_row(
                str(i),
                f.action_url[:45],
                f.method,
                f.user_field,
                f.pass_field,
                f.csrf_field or "[dim]none[/]",
                str(len(f.hidden_fields)),
            )

        console.print(table)
        console.print()
        console.print(f"  [bold green]>[/] Pages crawled: [bold]{len(visited)}[/]  Forms found: [bold]{len(unique_forms)}[/]  Time: {elapsed:.1f}s")

        if unique_forms:
            console.print()
            console.print("  [bold cyan]>[/] Use [bold]auto-brute <url> <user:pass_file>[/] to attack these forms")

        return {
            "success": True,
            "forms": [
                {
                    "action_url": f.action_url,
                    "method": f.method,
                    "user_field": f.user_field,
                    "pass_field": f.pass_field,
                    "hidden_fields": f.hidden_fields,
                    "csrf_field": f.csrf_field,
                    "csrf_token": f.csrf_token,
                    "enctype": f.enctype,
                }
                for f in unique_forms
            ],
            "pages_crawled": len(visited),
            "elapsed": elapsed,
        }

    def _extract_forms(self, page_url: str, resp) -> list[LoginForm]:
        """Extract all forms from an HTML page (delegates to engine.crawler)."""
        return extract_forms(resp.text, page_url)

    def _extract_links(self, base_url: str, html: str) -> list[str]:
        """Extract same-domain links from HTML (delegates to engine.crawler)."""
        return extract_links(base_url, html)

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is on the same domain as target (delegates to engine.crawler)."""
        return is_same_domain(url, self.target.host)
