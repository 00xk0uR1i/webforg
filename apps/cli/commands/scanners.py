"""Quick-attack scanner commands (scan/crawl/auto-brute/bruteforce/spray/enum/creds/secret-scan/cve-scan/sploitus-exploit).

Moved verbatim from ``webforg/cli.py`` (Phase 10).  These commands wire a
parsed target (``TargetService``) into a module instance (``ModuleService``)
instead of doing their own URL parsing / HTTP logic.
"""

from __future__ import annotations

from webforg.apps.cli.console import console
from webforg.core.services import ScanServiceError
from webforg.core.theme import error_msg, glitch_text


class ScannerCommandsMixin:
    """Command handlers for quick attack / scan workflows."""

    def cmd_scan(self, args: list[str]):
        """Quick auto-scan: run all checks against a target URL."""
        if not args:
            console.print("[red]Usage: scan <url> [checks:all,sqli,xss,lfi,ssti,ssrf,headers,ssl,tech][/]")
            return

        url = self._normalize_url(args[0])
        checks = args[1] if len(args) > 1 else "all"

        console.print()
        glitch_text(f"  >> INITIATING FULL SCAN: {url}", iterations=4, delay=0.03)
        console.print()

        try:
            self.scan_service.scan_url(url, checks=checks)
        except ScanServiceError as e:
            error_msg(str(e))

    def cmd_crawl(self, args: list[str]):
        """Crawl target for login forms: crawl <url> [depth]"""
        if not args:
            console.print("[red]Usage: crawl <url> [depth]")
            console.print("[dim]  Example: crawl https://target.com 2[/]")
            return

        url = self._normalize_url(args[0])
        depth = int(args[1]) if len(args) > 1 else 1

        console.print()
        glitch_text(f"  >> CRAWLING FOR FORMS: {url}", iterations=3, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/form_crawler")
        if not mod:
            error_msg("Form crawler module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("DEPTH", depth)
        mod.set_option("TIMEOUT", 10)
        self.module_service.run(mod)

    def cmd_auto_brute(self, args: list[str]):
        """Auto-brute: crawl for forms then brute force them: auto-brute <url> <user:pass_file>"""
        if not args:
            console.print("[red]Usage: auto-brute <url> <user:pass_file> [depth]")
            console.print("[dim]  Example: auto-brute https://target.com creds.txt 2[/]")
            return

        url = self._normalize_url(args[0])
        creds_file = args[1] if len(args) > 1 else ""
        depth = int(args[2]) if len(args) > 2 else 1

        console.print()
        glitch_text(f"  >> AUTO-BRUTE: {url}", iterations=4, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/auto_bruteforce")
        if not mod:
            error_msg("Auto-brute module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("CREDS_FILE", creds_file)
        mod.set_option("DEPTH", depth)
        mod.set_option("TIMEOUT", 10)
        mod.set_option("THREADS", 1)
        mod.set_option("DELAY", 0.5)
        mod.set_option("MAX_ATTEMPTS", 200)
        self.module_service.run(mod)

    def cmd_sploitus_exploit(self, args: list[str]):
        """Run Sploitus exploits against a target: sploitus-exploit <url> [cve|tech] [keywords]"""
        if not args:
            console.print("[red]Usage: sploitus-exploit <url> [search_type] [keywords]")
            console.print("[dim]  Examples:[/]")
            console.print("[dim]    sploitus-exploit https://target.com              # auto-detect & exploit[/]")
            console.print("[dim]    sploitus-exploit https://target.com cve CVE-2021-3129  # specific CVE[/]")
            console.print("[dim]    sploitus-exploit https://target.com tech WordPress,PHP  # by technology[/]")
            return

        url = self._normalize_url(args[0])

        # Smart arg parsing: detect CVE IDs, tech keywords, or CMS names
        remaining = args[1:] if len(args) > 1 else []
        search_type = "auto"
        keywords = None

        if remaining:
            # Join all remaining args and check if any part looks like a CVE
            full_arg = " ".join(remaining)
            import re
            # Match full CVE (CVE-YYYY-NNNNN) or partial (CVE-YYYY-NNN)
            cve_match = re.search(r'(CVE[-_]\d{4}[-_]?\d+)', full_arg, re.IGNORECASE)
            if cve_match:
                search_type = "cve"
                keywords = cve_match.group(1).upper().replace("_", "-")
            elif remaining[0].lower() == "cve" and len(remaining) > 1:
                search_type = "cve"
                keywords = " ".join(remaining[1:]).upper()
            elif remaining[0].lower() == "tech" and len(remaining) > 1:
                search_type = "tech"
                keywords = " ".join(remaining[1:])
            elif remaining[0].lower() in ("wordpress", "joomla", "drupal", "magento", "prestashop", "opencart"):
                search_type = "cms"
                keywords = remaining[0].lower()
            else:
                # Could be a CMS name or tech string
                first = remaining[0].lower()
                if first in ("wordpress", "wp"):
                    search_type = "cms"
                    keywords = "wordpress"
                elif first in ("joomla",):
                    search_type = "cms"
                    keywords = "joomla"
                elif first in ("drupal",):
                    search_type = "cms"
                    keywords = "drupal"
                elif first in ("magento",):
                    search_type = "cms"
                    keywords = "magento"
                else:
                    search_type = "tech"
                    keywords = full_arg

        target = self.target_service.parse_url(url)

        console.print()
        glitch_text(f"  >> SPLOITUS EXPLOIT: {url}", iterations=4, delay=0.03)
        console.print()

        mod = self.module_service.instantiate("exploits/sploitus_exploit")
        if not mod:
            error_msg("Sploitus exploit module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("TIMEOUT", 10)

        if search_type == "cve" and keywords:
            mod.set_option("CVE", keywords)
            mod.set_option("SEARCH_BY", "cve")
        elif search_type == "tech" and keywords:
            mod.set_option("TECHS", keywords)
            mod.set_option("SEARCH_BY", "tech")
        elif search_type == "cms" and keywords:
            mod.set_option("CMS", keywords)
            mod.set_option("SEARCH_BY", "cms")
        else:
            mod.set_option("SEARCH_BY", "auto")

        mod.set_option("LIMIT", 30)
        mod.set_option("THREADS", 3)
        self.module_service.exploit(mod)

    def cmd_secret_scan(self, args: list[str]):
        """Scan for secrets, passwords, keys, hashes, emails, and hidden files: secret-scan <url> [depth]"""
        if not args:
            console.print("[red]Usage: secret-scan <url> [depth]")
            console.print("[dim]  Examples:[/]")
            console.print("[dim]    secret-scan https://target.com           # scan depth 2[/]")
            console.print("[dim]    secret-scan https://target.com 4         # deeper crawl[/]")
            return

        url = self._normalize_url(args[0])
        depth = int(args[1]) if len(args) > 1 else 2

        console.print()
        glitch_text(f"  >> SECRET SCAN: {url}", iterations=4, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/secret_scanner")
        if not mod:
            error_msg("Secret scanner module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("TIMEOUT", 10)
        mod.set_option("DEPTH", depth)
        mod.set_option("THREADS", 5)
        mod.set_option("CRACK_HASHES", True)
        mod.set_option("DECODE_BASE64", True)
        self.module_service.run(mod)

    def cmd_bruteforce(self, args: list[str]):
        """Quick brute force: bruteforce <url> <usernames_file> [wordlist]"""
        if not args:
            console.print("[red]Usage: bruteforce <url> <usernames_file_or_user> [wordlist_file][/]")
            console.print("[dim]  Example: bruteforce target.com/login users.txt wordlist.txt[/]")
            return

        url = self._normalize_url(args[0])
        usernames = args[1] if len(args) > 1 else ""
        wordlist = args[2] if len(args) > 2 else None

        console.print()
        glitch_text(f"  >> BRUTE FORCE: {url}", iterations=3, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/brute_force")
        if not mod:
            error_msg("Brute force module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("TARGETURI", target.raw_path or "/login")
        mod.set_option("USERNAME", usernames)
        if wordlist:
            mod.set_option("WORDLIST", wordlist)
        mod.set_option("DELAY", 0.5)
        mod.set_option("THREADS", 1)
        self.module_service.run(mod)

    def cmd_spray(self, args: list[str]):
        """Quick password spray: spray <url> <usernames_file> [passwords_file]"""
        if not args:
            console.print("[red]Usage: spray <url> <usernames_file_or_list> [passwords_file][/]")
            console.print("[dim]  Example: spray http://target.com/login users.txt passwords.txt[/]")
            return

        url = self._normalize_url(args[0])
        usernames = args[1] if len(args) > 1 else ""
        passwords = args[2] if len(args) > 2 else None

        console.print()
        glitch_text(f"  >> PASSWORD SPRAY: {url}", iterations=3, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/password_spray")
        if not mod:
            error_msg("Password spray module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("TARGETURI", target.raw_path or "/login")
        mod.set_option("USERNAMES", usernames)
        if passwords:
            mod.set_option("PASSWORDS", passwords)
        mod.set_option("DELAY", 2.0)
        self.module_service.run(mod)

    def cmd_enum(self, args: list[str]):
        """Enumerate valid usernames: enum <url> <usernames_file>"""
        if not args:
            console.print("[red]Usage: enum <url> <usernames_file_or_list>[/]")
            console.print("[dim]  Example: enum http://target.com/login users.txt[/]")
            return

        url = self._normalize_url(args[0])
        usernames = args[1] if len(args) > 1 else ""

        console.print()
        glitch_text(f"  >> ACCOUNT ENUMERATION: {url}", iterations=3, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/account_enum")
        if not mod:
            error_msg("Account enum module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("TARGETURI", target.raw_path or "/login")
        mod.set_option("USERNAMES", usernames)
        self.module_service.run(mod)

    def cmd_creds(self, args: list[str]):
        """Credential stuffing: creds <url> <user:pass_file>"""
        if not args:
            console.print("[red]Usage: creds <url> <credentials_file>[/]")
            console.print("[dim]  File format: user:pass (one per line)[/]")
            console.print("[dim]  Example: creds http://target.com/login leaked_creds.txt[/]")
            return

        url = self._normalize_url(args[0])
        creds_file = args[1] if len(args) > 1 else ""

        console.print()
        glitch_text(f"  >> CREDENTIAL STUFFING: {url}", iterations=3, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("auxiliary/scanners/credential_stuffing")
        if not mod:
            error_msg("Credential stuffing module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("TARGETURI", target.raw_path or "/login")
        mod.set_option("CREDS_FILE", creds_file)
        mod.set_option("THREADS", 5)
        mod.set_option("DELAY", 0.3)
        self.module_service.run(mod)

    def cmd_cve_scan(self, args: list[str]):
        """Auto-scan all CVE modules against a target."""
        if not args:
            console.print("[red]Usage: cve-scan <url> [mode:smart|all] [username] [password][/]")
            console.print("[dim]  Examples:[/]")
            console.print("[dim]    cve-scan https://target.com              # smart fingerprint-driven scan[/]")
            console.print("[dim]    cve-scan https://target.com all          # run ALL CVE checks[/]")
            console.print("[dim]    cve-scan https://target.com smart admin P@ss  # with credentials[/]")
            return

        url = self._normalize_url(args[0])
        mode = args[1] if len(args) > 1 else "smart"
        username = args[2] if len(args) > 2 else None
        password = args[3] if len(args) > 3 else None

        console.print()
        glitch_text(f"  >> CVE AUTO-SCAN: {url}", iterations=4, delay=0.03)
        console.print()

        target = self.target_service.parse_url(url)
        mod = self.module_service.instantiate("exploits/cve/cve_autoscan")
        if not mod:
            error_msg("CVE auto-scan module not found")
            return
        self.target_service.apply_to_module(mod, target)
        mod.set_option("MODE", mode)
        if username:
            mod.set_option("USERNAME", username)
        if password:
            mod.set_option("PASSWORD", password)
        mod.set_option("LHOST", self._global_options.get("LHOST"))
        mod.set_option("LPORT", self._global_options.get("LPORT", 4444))

        result = self.module_service.exploit(mod)
        console.print()
        console.print(result.output)
        if result.extra and result.extra.get("vulnerable_count", 0) > 0:
            console.print()
            console.print("[bold green]  Use 'use <module_path>' then 'set' + 'exploit' to attack.[/]")
