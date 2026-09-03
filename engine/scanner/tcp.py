"""TCP port scanner with banner grabbing and service identification.

Real implementation migrated from ``webforg.core.scanner`` (Phase 6).  The
legacy path remains a compatibility facade re-exporting from here.  Pure socket
logic — no framework imports.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_TIMEOUT = 1.5
MAX_CONCURRENCY = 256

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    631, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4443,
    5000, 5001, 5432, 5900, 5985, 5986, 6379, 7001, 8000, 8008, 8009, 8080,
    8081, 8085, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211,
    15672, 27017, 50000,
]

# Well-known service names for port-only identification (used before banner).
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "smtp",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker", 3000: "web",
    3306: "mysql", 3389: "rdp", 5000: "web", 5432: "postgresql", 5900: "vnc",
    5985: "winrm-http", 5986: "winrm-https", 6379: "redis", 7001: "weblogic",
    8000: "web", 8080: "http-alt", 8088: "http-alt", 8443: "https-alt",
    8888: "web", 9000: "web", 9090: "web", 9200: "elasticsearch",
    10000: "webadmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 50000: "sap",
}

_BANNER_HINTS = [
    ("ssh", (b"SSH-",)),
    ("http", (b"HTTP/", b"<html", b"<!DOCTYPE", b"Server:")),
    ("ftp", (b"220 ", b"FTP", b"230 ")),
    ("smtp", (b"220 ", b"ESMTP", b"SMTP")),
    ("imap", (b"* OK", b"IMAP")),
    ("pop3", (b"+OK", b"POP3")),
    ("mssql", (b"SQL Server", b".S.u.n.")),
    ("mysql", (b"mysql", b"5.", b"MariaDB")),
    ("postgresql", (b"PostgreSQL", b"postgres")),
    ("redis", (b"redis_version", b"+PONG", b"REDIS")),
    ("mongodb", (b"istmaster", b"ismaster", b"serverStatus")),
    ("telnet", (b"login:", b"Password:", b"# ")),
    ("vnc", (b"RFB ", b"RFB")),
    ("rdp", (b"\x03\x00\x00",)),
    ("docker", (b"HTTP/1.1 200 OK",)),
    ("elasticsearch", (b"elasticsearch",)),
    ("weblogic", (b"WebLogic", b"BEA-")),
    ("oracle", (b"TNS", b".o.r.c.l.e.")),
    ("apache", (b"Apache",)),
    ("nginx", (b"nginx",)),
    ("iis", (b"Microsoft-IIS",)),
    ("openssh", (b"OpenSSH",)),
    ("vsftpd", (b"vsFTPd",)),
    ("proftpd", (b"ProFTPD",)),
    ("samba", (b"smbd", b"Samba")),
    ("hp-proliant", (b"HP HTTP",)),
    ("cisco", (b"cisco",)),
]


@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    ssl: bool = False

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "ssl": self.ssl,
        }


@dataclass
class ScanOptions:
    host: str
    ports: list[int] = field(default_factory=lambda: list(COMMON_PORTS))
    timeout: float = DEFAULT_TIMEOUT
    workers: int = 64
    grab_banners: bool = True
    use_ssl: bool = False
    progress: Optional[callable] = None


def _service_from_banner(banner: str) -> tuple[str, str, str]:
    """Return (service, product, version) guessed from a banner string."""
    b = banner.encode("latin-1", "replace") if isinstance(banner, str) else banner
    low = banner.lower() if isinstance(banner, str) else b.decode("latin-1", "replace").lower()
    product = ""
    version = ""
    # Prefer an explicit Server: header for web banners.
    if "server:" in low:
        idx = low.index("server:")
        server_line = banner[idx:].splitlines()[0].split(":", 1)[1].strip()
        product = server_line.split("/")[0].strip()
        rest = server_line.split("/", 1)
        if len(rest) == 2:
            ver = rest[1].strip()
            for t in ver.split():
                if t and (t[0].isdigit() or t[0] == "v"):
                    version = t.rstrip(",")
                    break
    for svc, markers in _BANNER_HINTS:
        for m in markers:
            if m in b:
                service = svc
                if not product:
                    product = svc
                if not version:
                    for name in ("OpenSSH", "nginx", "Apache", "vsFTPd", "ProFTPD", "MySQL", "PostgreSQL", "Microsoft-IIS", "Pure-FTPd"):
                        if name.lower() in low:
                            product = name
                            rest = low[low.index(name.lower()) + len(name):]
                            toks = rest.split()
                            for t in toks[:3]:
                                if t and t[0].isdigit():
                                    version = t.rstrip(",")
                                    break
                            break
                return service, product, version
    return "", product, version


def _banner_grab(host: str, port: int, timeout: float, use_ssl: bool) -> dict:
    banner = ""
    ssl_flag = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if use_ssl:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        banner = tls.recv(2048).decode("latin-1", "replace").strip()[:500]
                        ssl_flag = True
                except Exception:
                    pass
            if not banner:
                try:
                    banner = sock.recv(2048).decode("latin-1", "replace").strip()[:500]
                except Exception:
                    pass
            if not banner:
                try:
                    sock.sendall(b"\r\n")
                    banner = sock.recv(2048).decode("latin-1", "replace").strip()[:500]
                except Exception:
                    pass
            if not banner:
                try:
                    sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
                    banner = sock.recv(2048).decode("latin-1", "replace").strip()[:500]
                except Exception:
                    pass
    except Exception:
        pass
    return {"banner": banner, "ssl": ssl_flag}


def _probe(host: str, port: int, opts: ScanOptions) -> PortResult:
    res = PortResult(port=port)
    try:
        with socket.create_connection((host, port), timeout=opts.timeout):
            res.state = "open"
    except Exception:
        return res
    res.service = PORT_SERVICES.get(port, "")
    if opts.grab_banners:
        info = _banner_grab(host, port, opts.timeout, opts.use_ssl)
        res.banner = info["banner"]
        res.ssl = info["ssl"] or res.ssl
        if res.banner:
            svc, prod, ver = _service_from_banner(res.banner)
            if svc and (not res.service or svc != "http"):
                res.service = svc
            res.product = prod or res.service
            res.version = ver
    return res


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '80,443,8000-8100,443' into a sorted unique list."""
    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo, hi = chunk.split("-", 1)
                lo, hi = int(lo), int(hi)
                if lo < 1 or hi > 65535 or lo > hi:
                    continue
                ports.update(range(lo, hi + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(chunk)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)


def scan(host: str, ports: list[int], timeout: float = DEFAULT_TIMEOUT,
         workers: int = 64, grab_banners: bool = True, use_ssl: bool = False,
         progress: Optional[callable] = None) -> dict:
    """Run a threaded TCP connect scan and return structured results."""
    host = host.strip()
    if not host:
        raise ValueError("No target host supplied")
    opts = ScanOptions(host=host, ports=ports, timeout=timeout, workers=max(1, min(workers, MAX_CONCURRENCY)),
                       grab_banners=grab_banners, use_ssl=use_ssl, progress=progress)
    started = time.time()
    open_ports: list[PortResult] = []
    done = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=opts.workers) as pool:
        futs = {pool.submit(_probe, host, p, opts): p for p in ports}
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception:
                res = None
            done += 1
            if opts.progress and done % 10 == 0:
                opts.progress(done, len(ports))
            if res and res.state == "open":
                open_ports.append(res)
    open_ports.sort(key=lambda r: r.port)
    return {
        "host": host,
        "ports_scanned": len(ports),
        "ports_open": len(open_ports),
        "duration": round(time.time() - started, 2),
        "results": [r.to_dict() for r in open_ports],
    }
