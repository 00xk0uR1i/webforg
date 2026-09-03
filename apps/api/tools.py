"""Form-crawler / auto-brute / secret-scan / fuzz routes for the WebForge HTTP API."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from webforg.apps.api.models import (
    AutoBruteReq,
    FormCrawlerReq,
    FuzzReq,
    SecretScanReq,
)
from webforg.apps.api.shared import _module_service, _parse_url

router = APIRouter()


@router.post("/api/form-crawler")
def api_form_crawler(req: FormCrawlerReq):
    """Crawl target for login forms."""
    host, port, ssl_flag, path = _parse_url(req.target)
    mod = _module_service.instantiate("auxiliary/scanners/form_crawler")
    if not mod:
        raise HTTPException(500, "Form crawler module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("DEPTH", req.depth)
    mod.set_option("MAX_PAGES", req.max_pages)
    result = _module_service.run(mod)
    return result

@router.post("/api/auto-brute")
def api_auto_brute(req: AutoBruteReq):
    """Auto-brute: crawl for forms then brute force them."""
    host, port, ssl_flag, path = _parse_url(req.target)
    mod = _module_service.instantiate("auxiliary/scanners/auto_bruteforce")
    if not mod:
        raise HTTPException(500, "Auto-brute module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("CREDS_FILE", req.creds_file)
    mod.set_option("DEPTH", req.depth)
    mod.set_option("THREADS", req.threads)
    mod.set_option("DELAY", req.delay)
    mod.set_option("MAX_ATTEMPTS", req.max_attempts)
    result = _module_service.run(mod)
    return result

@router.post("/api/secret-scan")
def api_secret_scan(req: SecretScanReq):
    """Run Secret Scanner ELITE against a target."""
    host, port, ssl_flag, path = _parse_url(req.target)
    mod = _module_service.instantiate("auxiliary/scanners/secret_scanner")
    if not mod:
        raise HTTPException(500, "Secret Scanner module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("TIMEOUT", req.timeout)
    mod.set_option("DEPTH", req.depth)
    mod.set_option("THREADS", req.threads)
    mod.set_option("CHECK_GIT", req.check_git)
    mod.set_option("CHECK_CLOUD", req.check_cloud)
    mod.set_option("CHECK_CORS", req.check_cors)
    mod.set_option("CHECK_GRAPHQL", req.check_graphql)
    mod.set_option("CHECK_JS", req.check_js)
    mod.set_option("CHECK_WEBSOCKETS", req.check_websockets)
    mod.set_option("CRACK_HASHES", req.crack_hashes)
    mod.set_option("CRACK_JWT", req.crack_jwt)
    result = _module_service.run(mod)
    return result

@router.post("/api/fuzz/run")
def api_fuzz_run(req: FuzzReq):
    """Run WebFuzzer: directory fuzzing + parameter spider (RCE/XSS testing)."""
    host, port, ssl_flag, path = _parse_url(req.target)
    mod = _module_service.instantiate("auxiliary/scanners/web_fuzzer")
    if not mod:
        raise HTTPException(500, "WebFuzzer module not found")
    mod.set_option("RHOSTS", host)
    mod.set_option("RPORT", port)
    mod.set_option("SSL", ssl_flag)
    mod.set_option("TARGETURI", path)
    mod.set_option("TIMEOUT", req.timeout)
    mod.set_option("THREADS", req.threads)
    mod.set_option("FUZZ_DIRS", req.fuzz_dirs)
    mod.set_option("FUZZ_WORDLIST", req.wordlist)
    mod.set_option("MAX_DIRS", req.max_dirs)
    mod.set_option("SPIDER", req.spider)
    mod.set_option("MAX_CRAWL", req.max_crawl)
    mod.set_option("TEST_RCE", req.test_rce)
    mod.set_option("TEST_XSS", req.test_xss)
    mod.set_option("MAX_PARAM_TESTS", req.max_param_tests)
    mod.set_option("EXTENSIONS", req.extensions)
    mod.set_option("MAX_DEPTH", req.max_depth)
    mod.set_option("EXTRA_HEADERS", req.extra_headers)
    mod.set_option("WAF_BYPASS", req.waf_bypass)
    result = _module_service.run(mod)
    return result
