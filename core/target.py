"""Target representation and fingerprinting."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import httpx

from webforg.engine.fingerprint import analyze_headers, analyze_html, favicon_hash


@dataclass
class Target:
    """Represents a single web target."""
    
    host: str
    port: int = 80
    ssl: bool = False
    path: str = "/"
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=lambda: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    proxy: Optional[str] = None
    timeout: float = 10.0
    
    # Internal
    _client: Optional[httpx.Client] = None
    _fingerprint: Optional[dict] = None
    
    def __post_init__(self):
        if self.port == 443:
            self.ssl = True
    
    @property
    def base_url(self) -> str:
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.host}:{self.port}{self.path}"
    
    @property
    def session(self) -> httpx.Client:
        if self._client is None:
            transport_kwargs = {}
            if self.proxy:
                transport_kwargs["transport"] = httpx.HTTPTransport(proxy=self.proxy)
            self._client = httpx.Client(
                cookies=self.cookies,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                follow_redirects=True,
                **transport_kwargs,
            )
        return self._client
    
    def fingerprint(self) -> dict:
        """Auto-detect web technologies on target.
        
        Returns dict with keys: server, cms, framework, js_frameworks, 
                                 technologies, waf, os, favicon_hash
        """
        if self._fingerprint is not None:
            return self._fingerprint
        
        result = {
            "server": None,
            "cms": None,
            "framework": None,
            "js_frameworks": [],
            "technologies": [],
            "waf": None,
            "os": None,
            "favicon_hash": None,
            "raw_headers": {},
        }
        
        try:
            resp = self.session.get(self.base_url)
            result["raw_headers"] = dict(resp.headers)

            # Header analysis (server, set-cookie, x-powered-by)
            header_info = analyze_headers(dict(resp.headers))
            result["server"] = header_info["server"]
            result["technologies"] = header_info["technologies"]
            result["js_frameworks"].extend(header_info["js_frameworks"])

            # HTML analysis (CMS / JS frameworks)
            html_info = analyze_html(resp.text)
            result["cms"] = html_info["cms"]
            result["js_frameworks"].extend(html_info["js_frameworks"])

            # Favicon hash
            try:
                favicon_url = f"{self.base_url.rstrip('/')}/favicon.ico"
                fav_resp = self.session.get(favicon_url)
                if fav_resp.status_code == 200:
                    result["favicon_hash"] = favicon_hash(fav_resp.content)
            except Exception:
                pass
            
        except Exception as e:
            result["error"] = str(e)
        
        self._fingerprint = result
        return result
    
    def __str__(self) -> str:
        return self.base_url
    
    def __repr__(self) -> str:
        return f"<Target {self.base_url}>"


# favicon hash DB (abbreviated — expand with real data)
KNOWN_FAVICON_HASHES = {
    "116323821": "WordPress",
    "-920601005": "Joomla",
    "1578938751": "Drupal",
    "-1831172575": "Jenkins",
    "81586312": "Tomcat",
    "-1270006812": "Confluence",
    "-2135283795": "GitHub",
}
