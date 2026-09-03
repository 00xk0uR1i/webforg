"""Apple ID Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Apple ID Credential Tester"
    description = "Tests Apple ID credentials via the web sign-in flow in a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "apple_id"
    browser_login_url = "https://account.apple.com/sign-in"
    username_selector = "input[name=accountName]"
    username_submit_selector = "button:has-text('Continue')"
    password_selector = "input[name=password]"
    submit_enter = True
    submit_selectors = ("button:has-text('Sign In')", "button[type=submit]")
    browser_login_paths = ("/sign-in", "/signin")
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "confirm your identity", "trusted device",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "confirm it's you",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "sign-in attempt limit",
    )
    invalid_markers = (
        "your apple id or password was incorrect", "incorrect apple id or password",
        "incorrect password", "wrong password", "invalid password",
        "your account doesn't have", "could not be found", "does not exist",
    )
