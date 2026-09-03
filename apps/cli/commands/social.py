"""Social media auth commands (social/social_enum/social_reuse).

Moved verbatim from ``webforg/cli.py`` (Phase 10).  The ``social`` handler
keeps its historical direct ``attempt_login()`` call (module orchestration is
not applied here) to avoid changing CLI behaviour.
"""

from __future__ import annotations

from webforg.apps.cli.console import console
from webforg.core.theme import error_msg, glitch_text, success_msg


class SocialCommandsMixin:
    """Command handlers for social media auth testing."""

    def cmd_social(self, args: list[str]):
        """Test creds on specific platform: social <platform> <email> <password>"""
        if len(args) < 3:
            console.print("[red]Usage: social <platform> <email> <password>[/]")
            console.print("[dim]  Platforms: instagram, facebook, twitter, linkedin, tiktok, reddit, discord, github, google[/]")
            console.print("[dim]  Example: social instagram test@test.com password123[/]")
            return

        platform, email, password = args[0].lower(), args[1], args[2]

        console.print()
        glitch_text(f"  >> SOCIAL AUTH TEST: {platform.upper()}", iterations=3, delay=0.03)
        console.print()

        mod = self.module_service.instantiate(f"auth/platforms/{platform}")
        if not mod:
            error_msg(f"Platform module '{platform}' not found. Available: instagram facebook twitter linkedin tiktok reddit discord github google")
            return

        mod.set_option("RHOSTS", f"{platform}.com")
        mod.set_option("USERNAME", email)
        mod.set_option("PASSWORD", password)
        result = mod.attempt_login(email, password)

        if result.success:
            success_msg(f"Login successful on {platform}! User: {result.username}")
            if result.session_token:
                console.print(f"  [green]>[/] Token: {result.session_token[:30]}...")
        else:
            error_msg(f"Login failed: {result.error_type}")

    def cmd_social_enum(self, args: list[str]):
        """Enumerate user across platforms: social_enum <email_or_username>"""
        if not args:
            console.print("[red]Usage: social_enum <email_or_username>[/]")
            console.print("[dim]  Example: social_enum john@example.com[/]")
            return

        target = args[0]
        console.print()
        glitch_text(f"  >> SOCIAL USER ENUMERATION: {target}", iterations=3, delay=0.03)
        console.print()

        mod = self.module_service.instantiate("auth/user_enumerator")
        if not mod:
            error_msg("User enumerator module not found")
            return

        if "@" in target:
            mod.set_option("EMAIL", target)
            mod.set_option("MODE", "email")
        else:
            mod.set_option("USERNAME", target)
            mod.set_option("MODE", "username")

        mod.set_option("PLATFORMS", "all")
        self.module_service.run(mod)

    def cmd_social_reuse(self, args: list[str]):
        """Test same creds across all platforms: social_reuse <email> <password>"""
        if len(args) < 2:
            console.print("[red]Usage: social_reuse <email> <password>[/]")
            console.print("[dim]  Example: social_reuse john@test.com password123[/]")
            console.print("[dim]  Tests same email:pass on all integrated platforms.[/]")
            return

        email, password = args[0], args[1]

        console.print()
        glitch_text(f"  >> CREDENTIAL REUSE TEST: {email}", iterations=3, delay=0.03)
        console.print()

        mod = self.module_service.instantiate("auth/multi_platform_runner")
        if not mod:
            error_msg("Multi-platform runner module not found")
            return

        mod.set_option("EMAIL", email)
        mod.set_option("PASSWORD", password)
        mod.set_option("PLATFORMS", "all")
        self.module_service.run(mod)
