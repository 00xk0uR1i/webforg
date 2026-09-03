"""LinkedIn Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "LinkedIn Credential Tester"
    description = "Tests credentials against LinkedIn's web login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "linkedin"
    browser_login_url = "https://www.linkedin.com/login"
    username_selector = "input[type=email]:visible"
    password_selector = "input[type=password]:visible"
    browser_login_paths = ("/login", "/uas/login")
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "verify it's you", "check your messages",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "confirm it's you",
        "challenge", "verify your identity",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "please wait a few", "you've been rate",
    )
    invalid_markers = (
        "that's not the right password", "incorrect password", "wrong password",
        "password is incorrect", "enter a valid email address", "valid email address",
        "please try again", "no account found", "this account doesn't exist",
        "email address isn't associated", "بريد إلكتروني صالح",
    )
