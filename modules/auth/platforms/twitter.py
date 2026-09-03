"""Twitter/X Credential Tester — headless-browser login flow.

X's API requires OAuth 2.0 PKCE + signed request headers, so the web flow is
driven through a real Chromium instead.
"""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Twitter/X Credential Tester"
    description = "Tests credentials against Twitter/X's web login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "twitter"
    browser_login_url = "https://x.com/login"
    username_selector = "input[name=username_or_email]"
    password_selector = "input[name=password]"
    submit_enter = True
    submit_selectors = ("div[role=button]:text-is('Log in')", "button[type=submit]")
    browser_login_paths = ("/i/jf/onboarding", "/i/flow/login", "/login")
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "check your email", "confirm your identity", "one-time password",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "confirm it's you",
        "are you a robot", "we've detected a problem", "phone verification",
    )
    rate_markers = (
        "we've temporarily limited your login", "temporarily limited",
        "too many attempts", "try again later", "rate limit", "rate-limited",
        "temporarily", "wait a bit", "slow down",
    )
    invalid_markers = (
        "incorrect password", "wrong password", "invalid username or password",
        "the password was incorrect", "username and password you entered",
        "did not match", "invalid login", "account doesn't exist",
        "user not found", "that account doesn't exist", "no account found",
    )
