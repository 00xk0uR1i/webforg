"""Reddit Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Reddit Credential Tester"
    description = "Tests credentials against Reddit's web login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "reddit"
    browser_login_url = "https://www.reddit.com/login/"
    username_selector = "input[name=username]"
    password_selector = "input[name=password]"
    browser_login_paths = ("/login",)
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "confirm it's you",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "verify you're human",
    )
    rate_markers = (
        "too many attempts", "try again later", "slow down", "rate limit",
        "temporarily",
    )
    invalid_markers = (
        "incorrect username or password", "wrong password", "incorrect password",
        "password is incorrect", "invalid password", "no account with that username",
        "that username is taken by someone else", "doesn't exist",
    )
