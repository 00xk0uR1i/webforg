"""Subdomain enumeration auxiliary module."""

from webforg.core.module import BaseAuxiliaryModule, Option
from rich.console import Console
from rich.table import Table
import socket
import concurrent.futures

console = Console()


class Scanner(BaseAuxiliaryModule):
    """Subdomain enumeration via DNS resolution, wordlist brute-force, and certificate transparency."""

    name = "Subdomain Enumerator"
    description = "Enumerate subdomains using DNS brute-force and certificate transparency logs"
    author = "webforg"
    rank = "normal"

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "dns", "mx",
        "webmail", "cpanel", "admin", "portal", "dev", "staging", "test", "api",
        "app", "beta", "demo", "docs", "git", "gitlab", "jenkins", "ci", "cd",
        "jenkins", "jira", "confluence", "grafana", "kibana", "prometheus",
        "vpn", "remote", "gateway", "proxy", "lb", "haproxy", "nginx", "apache",
        "db", "mysql", "postgres", "redis", "mongo", "elastic", "rabbitmq",
        "shop", "store", "blog", "news", "forum", "support", "help", "status",
        "cdn", "static", "media", "assets", "img", "images", "downloads",
        "crm", "erp", "hr", "intranet", "internal", "secret", "backup",
        "m", "mobile", "wap", "touch",
    ]

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("DOMAIN", Option(str, required=True, description="Target domain (e.g. example.com)"))
        self.add_option("WORDLIST", Option(str, required=False, default=None, description="Path to custom wordlist"))
        self.add_option("THREADS", Option(int, required=False, default=10, description="Number of threads"))
        self.add_option("DNS_SERVER", Option(str, required=False, default=None, description="DNS server to use"))

    def _resolve(self, subdomain: str, domain: str, dns_server: str = None) -> dict:
        fqdn = f"{subdomain}.{domain}"
        try:
            if dns_server:
                import subprocess
                result = subprocess.run(
                    ["dig", f"@{dns_server}", fqdn, "+short", "+timeout=2"],
                    capture_output=True, text=True, timeout=5,
                )
                ips = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
            else:
                ip = socket.gethostbyname(fqdn)
                ips = [ip]

            return {"subdomain": fqdn, "ips": ips, "found": True}
        except (socket.gaierror, Exception):
            return {"subdomain": fqdn, "ips": [], "found": False}

    def _check_ct_logs(self, domain: str) -> list:
        """Query certificate transparency logs via crt.sh."""
        try:
            resp = self.target.session.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(f".{domain}") or line == domain:
                            if "*" not in line:
                                subdomains.add(line)
                return sorted(subdomains)
        except Exception:
            pass
        return []

    def run(self) -> dict:
        domain = self.get_option("DOMAIN")
        threads = self.get_option("THREADS") or 10
        dns_server = self.get_option("DNS_SERVER")
        wordlist_path = self.get_option("WORDLIST")

        subdomains = list(self.COMMON_SUBDOMAINS)

        if wordlist_path:
            try:
                with open(wordlist_path) as f:
                    custom = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    subdomains.extend(custom)
            except Exception as e:
                console.print(f"[red]Could not read wordlist: {e}[/]")

        console.print(f"[*] Enumerating subdomains for {domain} ({len(subdomains)} words)...")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._resolve, sub, domain, dns_server): sub
                for sub in subdomains
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result["found"]:
                    found.append(result)
                    console.print(f"  [green]+[/] {result['subdomain']} -> {', '.join(result['ips'])}")

        console.print(f"\n[*] Checking certificate transparency logs...")
        ct_subdomains = self._check_ct_logs(domain)
        for sub in ct_subdomains:
            if not any(f["subdomain"] == sub for f in found):
                found.append({"subdomain": sub, "ips": [], "found": True, "source": "crt.sh"})
                console.print(f"  [cyan]*[/] {sub} (via crt.sh)")

        table = Table(title=f"Subdomains for {domain}")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Address")
        table.add_column("Source")

        for entry in sorted(found, key=lambda x: x["subdomain"]):
            ips = ", ".join(entry["ips"]) if entry["ips"] else "N/A"
            source = entry.get("source", "DNS")
            table.add_row(entry["subdomain"], ips, source)

        console.print(table)
        console.print(f"\n[bold]Found {len(found)} subdomains[/]")

        return {"success": True, "domain": domain, "subdomains": found, "count": len(found)}
