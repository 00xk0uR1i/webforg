"""HTML crawling engine — form and link extraction from raw HTML.

Pure parsing logic migrated from ``webforg/modules/auxiliary/scanners/
form_crawler.py`` (Phase 6).  The module keeps its public surface and delegates
here.  No network, no framework — functions take strings and return plain
dataclasses/lists.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LoginForm:
    """Detected login form."""

    page_url: str
    action_url: str
    method: str = "POST"
    enctype: str = ""
    user_field: str = "username"
    pass_field: str = "password"
    hidden_fields: dict = field(default_factory=dict)
    csrf_token: str = ""
    csrf_field: str = ""
    extra_fields: list = field(default_factory=list)
    form_index: int = 0
    cookies: dict = field(default_factory=dict)

    def __str__(self):
        return f"{self.method} {self.action_url} (user={self.user_field}, pass={self.pass_field})"


# Common login-related paths to check
COMMON_LOGIN_PATHS = [
    "/", "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/admin", "/admin/login", "/administrator", "/wp-login.php",
    "/user/login", "/accounts/login", "/account/login",
    "/wp-admin/", "/manager", "/cpanel", "/webmail",
    "/portal", "/console", "/dashboard/login",
    "/api/auth/login", "/api/login", "/api/v1/login",
    "/_login", "/oauth/login", "/sso/login",
    "/xmlrpc.php", "/wp-json/wp/v2/users",
]


def extract_forms(html: str, page_url: str, form_index_base: int = 0) -> list[LoginForm]:
    """Extract all login forms from an HTML page.

    Mirrors the historical ``form_crawler._extract_forms`` behavior exactly:
    only forms with a password input (or a ``name="password"`` field) are
    returned.
    """
    forms = []

    form_pattern = re.compile(
        r'<form[^>]*>(.*?)</form>',
        re.DOTALL | re.IGNORECASE,
    )

    for match in form_pattern.finditer(html):
        form_html = match.group(0)
        form_tag = form_html.split(">")[0] + ">"

        if 'type=["\']password["\']' not in form_html.lower():
            if not re.search(r'name=["\'](?:password|pass|pwd)["\']', form_html, re.IGNORECASE):
                continue

        form = LoginForm(page_url=page_url, action_url="", form_index=form_index_base + len(forms))

        action_match = re.search(r'action=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
        if action_match:
            raw_action = action_match.group(1)
            form.action_url = urllib.parse.urljoin(page_url, raw_action) if raw_action else page_url
        else:
            form.action_url = page_url

        method_match = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
        form.method = (method_match.group(1).upper() if method_match else "POST")

        enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
        form.enctype = enctype_match.group(1) if enctype_match else ""

        inputs = re.findall(r'<input[^>]*>', form_html, re.IGNORECASE)
        for inp in inputs:
            name_match = re.search(r'name=["\']([^"\']+)["\']', inp)
            type_match = re.search(r'type=["\']([^"\']+)["\']', inp)
            value_match = re.search(r'value=["\']([^"\']*)["\']', inp)

            if not name_match:
                continue

            field_name = name_match.group(1)
            field_type = (type_match.group(1).lower() if type_match else "text")
            field_value = value_match.group(1) if value_match else ""

            if field_type == "hidden":
                form.hidden_fields[field_name] = field_value
                if any(kw in field_name.lower() for kw in ("csrf", "token", "_token", "nonce", "verify", "auth")):
                    form.csrf_token = field_value
                    form.csrf_field = field_name
            elif field_type == "password":
                form.pass_field = field_name
            elif field_type in ("text", "email", "tel"):
                if not form.user_field or form.user_field == "username":
                    form.user_field = field_name
            elif field_type not in ("submit", "button", "image", "hidden"):
                form.extra_fields.append(field_name)

        selects = re.findall(r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>.*?</select>', form_html, re.DOTALL | re.IGNORECASE)
        for sel_name in selects:
            form.hidden_fields[sel_name] = ""

        forms.append(form)

    return forms


def extract_links(base_url: str, html: str) -> list[str]:
    """Extract same-domain links from HTML.

    Mirrors the historical ``form_crawler._extract_links`` behavior exactly.
    """
    links = []
    parsed_base = urllib.parse.urlparse(base_url)

    for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        href = match.group(1)
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full_url = urllib.parse.urljoin(base_url, href)
        parsed = urllib.parse.urlparse(full_url)
        if parsed.netloc == parsed_base.netloc:
            clean = urllib.parse.urlunparse(parsed._replace(fragment=""))
            links.append(clean)

    return links


def is_same_domain(url: str, host: str) -> bool:
    """Check if a URL is on the given host (or relative).

    Mirrors the historical ``form_crawler._is_same_domain`` behavior exactly.
    """
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc == "" or parsed.netloc == host


__all__ = [
    "COMMON_LOGIN_PATHS",
    "LoginForm",
    "extract_forms",
    "extract_links",
    "is_same_domain",
]
