"""Pinterest Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Pinterest Credential Tester"
    description = "Tests credentials against Pinterest login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "pinterest"
    browser_login_url = "https://www.pinterest.com/login/"
    username_selector = "input[type=email]"
    password_selector = "input[type=password]"
    browser_login_paths = ("/login",)
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "confirm it's you",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "confirm it's you",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "many login attempts",
    )
    invalid_markers = (
        "incorrect password", "wrong password", "password is incorrect",
        "invalid password", "no account with that", "account doesn't exist",
        "doesn't exist", "we couldn't find", "does not belong to any account",
        "that doesn't look like an email",
    )
