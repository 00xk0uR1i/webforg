"""Shared API request/response models for the WebForge HTTP API.

Central definition of every Pydantic model consumed by the API routers in this
package so request contracts stay consistent across routers.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class SetOptionReq(BaseModel):
    module_path: str
    name: str
    value: str

class RunModuleReq(BaseModel):
    module_path: str

class GeneratePayloadReq(BaseModel):
    name: str
    lhost: str = "127.0.0.1"
    lport: int = 4444
    encoder: str = "none"

class WorkspaceReq(BaseModel):
    name: str = "default"

class CveSearchReq(BaseModel):
    query: str
    min_cvss: float = 0.0
    limit: int = 50

class DorkRunReq(BaseModel):
    query: str
    engines: Optional[list[str]] = None
    limit: int = 20
    target: Optional[str] = None

class TunnelStartReq(BaseModel):
    tool: str
    port: int = 80
    remote: str = ""
    remote_port: int = 80

class TunnelStopReq(BaseModel):
    tool: str

class TunnelManualReq(BaseModel):
    url: str = ""

class TemplateRenderReq(BaseModel):
    kind: str = "email"
    template_id: str
    variables: dict = {}

class OsintScanReq(BaseModel):
    query: str
    mode: str = "username"
    categories: Optional[list[str]] = None
    workers: int = 12

class BreachCheckReq(BaseModel):
    query: str
    mode: str = "email"

class LoginReq(BaseModel):
    password: str

class SessionDownloadReq(BaseModel):
    remote_path: str

class SessionUploadReq(BaseModel):
    remote_path: str
    data_b64: str

class CveExploitReq(BaseModel):
    cve_id: str

class ListenerReq(BaseModel):
    lhost: str = "0.0.0.0"
    lport: int = 4444
    payload_type: str = "shell"
    name: str = ""
    tls: bool = False

class FingerprintReq(BaseModel):
    host: str
    port: int = 80
    ssl: bool = False
    path: str = "/"

class ScanReq(BaseModel):
    url: str
    checks: str = "all"
    threads: int = 5

class BruteForceReq(BaseModel):
    url: str
    usernames: str
    passwords: str = ""
    wordlist: str = ""
    user_field: str = ""
    pass_field: str = ""
    fail_string: str = ""
    threads: int = 1
    delay: float = 0.5

class SprayReq(BaseModel):
    url: str
    usernames: str
    passwords: str = ""
    delay: float = 2.0

class EnumReq(BaseModel):
    url: str
    usernames: str

class CredsReq(BaseModel):
    url: str
    creds_file: str
    threads: int = 5
    delay: float = 0.3

class SploitusRunReq(BaseModel):
    url: str
    cve: str = ""
    techs: str = ""
    cms: str = ""
    search_by: str = "auto"
    limit: int = 30
    threads: int = 3
    command: str = "id"
    timeout: int = 10

class CmsExploitReq(BaseModel):
    url: str
    cms: str = "auto"
    lhost: str = "127.0.0.1"
    lport: int = 4444
    shell_lang: str = "auto"

class SocialLoginReq(BaseModel):
    platform: str
    email: str
    password: str
    delay: int = 3000

class SocialEnumReq(BaseModel):
    target: str
    platforms: str = "all"
    mode: str = "email"

class SocialReuseReq(BaseModel):
    email: str
    password: str
    platforms: str = "all"
    delay: int = 3000

class FormCrawlerReq(BaseModel):
    target: str
    depth: int = 2
    max_pages: int = 50

class AutoBruteReq(BaseModel):
    target: str
    creds_file: str
    depth: int = 1
    threads: int = 1
    delay: float = 0.5
    max_attempts: int = 200

class SecretScanReq(BaseModel):
    target: str
    depth: int = 3
    threads: int = 10
    timeout: int = 10
    check_git: bool = True
    check_cloud: bool = True
    check_cors: bool = True
    check_graphql: bool = True
    check_js: bool = True
    check_websockets: bool = True
    crack_hashes: bool = True
    crack_jwt: bool = True

class FuzzReq(BaseModel):
    target: str
    timeout: int = 8
    threads: int = 10
    fuzz_dirs: bool = True
    wordlist: str = ""
    max_dirs: int = 200
    spider: bool = True
    max_crawl: int = 25
    test_rce: bool = True
    test_xss: bool = True
    max_param_tests: int = 150
    extensions: str = ""
    max_depth: int = 0
    extra_headers: str = ""
    waf_bypass: bool = False

class AiAnalyzeReq(BaseModel):
    report: str
    format: str = "auto"

class AiChatReq(BaseModel):
    question: str
    context: str = ""

class AiExploitReq(BaseModel):
    vulnerability: str
    target: str
    details: str = ""

class AiCvePocReq(BaseModel):
    cve_id: str

class PortScanReq(BaseModel):
    host: str
    ports: str = "common"
    timeout: float = 1.5
    workers: int = 64
    grab_banners: bool = True
    use_ssl: bool = False

class CredsAddReq(BaseModel):
    target: str = ""
    username: str
    password: str = ""
    source: str = "manual"
    extra: str = ""

class CredsDeleteReq(BaseModel):
    id: int

class JobSubmitReq(BaseModel):
    action: str
    params: dict = {}
