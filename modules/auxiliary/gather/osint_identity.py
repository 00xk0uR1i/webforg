"""Unified OSINT identity gatherer — username, email, photo, and phone lookups."""

from __future__ import annotations
import hashlib
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from webforg.core.module import BaseAuxiliaryModule, Option

console = Console()

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

USERNAME_SITES = [
    ("GitHub", "https://github.com/{u}", []),
    ("Keybase", "https://keybase.io/{u}", []),
    ("Docker Hub", "https://hub.docker.com/u/{u}", []),
    ("Pastebin", "https://pastebin.com/u/{u}", []),
    ("AtCoder", "https://atcoder.jp/users/{u}", []),
    ("HackerOne", "https://hackerone.com/{u}", []),
    ("Bugcrowd", "https://bugcrowd.com/{u}", []),
    ("Codeberg", "https://codeberg.org/{u}", []),
    ("Steam Community", "https://steamcommunity.com/id/{u}", ["The specified profile could not be found"]),
    ("Roblox", "https://www.roblox.com/users/profile?username={u}", []),
    ("YouTube", "https://www.youtube.com/@{u}", []),
    ("OpenStreetMap", "https://www.openstreetmap.org/user/{u}", []),
    ("Mastodon.social", "https://mastodon.social/@{u}", []),
    ("DeviantArt", "https://www.deviantart.com/{u}", []),
    ("SoundCloud", "https://soundcloud.com/{u}", []),
    ("Dribbble", "https://dribbble.com/{u}", []),
    ("Behance", "https://www.behance.net/{u}", []),
    ("Buy Me a Coffee", "https://www.buymeacoffee.com/{u}", []),
    ("Gumroad", "https://gumroad.com/{u}", []),
    ("Flickr", "https://www.flickr.com/people/{u}", []),
    ("Vimeo", "https://vimeo.com/{u}", []),
    ("Patreon", "https://www.patreon.com/{u}", []),
    ("Bitbucket", "https://bitbucket.org/{u}/", []),
    ("Gravatar", "https://www.gravatar.com/{u}", []),
    ("HackerRank", "https://www.hackerrank.com/{u}", ["Something went wrong"]),
]

_DATA_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "opencv"))
YUNET_PATH = os.path.join(_DATA_DIR, "face_detection_yunet.onnx")
SFACE_PATH = os.path.join(_DATA_DIR, "face_recognition_sface.onnx")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Scanner(BaseAuxiliaryModule):
    """OSINT identity gatherer — locate and correlate a person by username, email, photo, or phone."""

    name = "OSINT Identity Gatherer"
    description = "OSINT on a person via username presence, email/breach lookup, photo reverse-search & face match, and phone validation"
    author = "webforg"
    rank = "normal"

    def _build_options(self) -> None:
        super()._build_options()
        self.add_option("INPUT", Option(str, required=True, description="Username, email, phone number, or path to a photo"))
        self.add_option("LOOKUP", Option(str, required=False, default="all", description="Checks to run: all,username,email,photo,phone"))
        self.add_option("PHOTO_DIR", Option(str, required=False, default=None, description="Directory of photos for local face matching"))
        self.add_option("PHOTO_URL", Option(str, required=False, default=None, description="Hosted URL of the photo (for reverse image search)"))
        self.add_option("THREADS", Option(int, required=False, default=8, description="Threads for username checks"))
        self.add_option("TIMEOUT", Option(int, required=False, default=10, description="HTTP timeout in seconds"))
        self.add_option("COUNTRY", Option(str, required=False, default="US", description="Default region for phone parsing"))
        self.add_option("HIBP_API_KEY", Option(str, required=False, default=None, description="HaveIBeenPwned v3 API key (optional)"))

    def run(self) -> dict:
        input_value = self.get_option("INPUT") or ""
        input_value = input_value.strip()
        lookup = {(x.strip().lower()) for x in (self.get_option("LOOKUP") or "all").split(",") if x.strip()}

        if not input_value:
            return {"success": False, "error": "INPUT is required"}

        self._client = httpx.Client(
            follow_redirects=True,
            timeout=self.get_option("TIMEOUT") or 10,
            verify=False,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"},
        )

        findings: list[dict] = []
        vector = self._detect_type(input_value)

        try:
            if vector == "photo":
                findings = self._handle_photo(input_value, lookup)
            elif vector == "email":
                findings = self._handle_email(input_value, lookup)
            elif vector == "phone":
                findings = self._handle_phone(input_value, lookup)
            else:
                findings = self._handle_username(input_value, lookup)
        finally:
            self._client.close()

        self._print_report(vector, input_value, findings)

        found = [f for f in findings if f.get("status") == "found"]
        return {
            "success": True,
            "input": input_value,
            "vector": vector,
            "findings": findings,
            "matches": len(found),
        }

    def _detect_type(self, value: str) -> str:
        if os.path.isfile(value):
            return "photo"
        if EMAIL_RE.match(value):
            return "email"
        digits = re.sub(r"[\s\-().+]", "", value)
        if digits.isdigit() and len(digits) >= 7:
            return "phone"
        return "username"

    def _wanted(self, lookup: set, key: str) -> bool:
        return "all" in lookup or key in lookup

    # ───────────────────────── username ─────────────────────────

    def _handle_username(self, username: str, lookup: set) -> list[dict]:
        if not self._wanted(lookup, "username"):
            return []
        threads = self.get_option("THREADS") or 8
        timeout = self.get_option("TIMEOUT") or 10
        results = []

        def check(site):
            name, url_tpl, not_found = site
            try:
                url = url_tpl.format(u=quote_plus(username))
                r = self._client.get(url, timeout=timeout)
                text = r.text
            except Exception as e:
                return {"site": name, "status": "error", "detail": type(e).__name__}
            if r.status_code in (401, 403, 429, 407):
                return {"category": "Username", "item": name, "status": "unknown", "detail": f"HTTP {r.status_code} (blocked)"}
            if r.status_code == 404:
                return {"category": "Username", "item": name, "status": "not_found", "detail": "HTTP 404"}
            if r.status_code >= 500:
                return {"category": "Username", "item": name, "status": "unknown", "detail": f"HTTP {r.status_code}"}
            for nf in not_found:
                if nf.lower() in text.lower():
                    return {"category": "Username", "item": name, "status": "not_found", "detail": nf}
            return {"category": "Username", "item": name, "status": "found", "detail": "HTTP 200", "url": url}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for future in as_completed([executor.submit(check, s) for s in USERNAME_SITES]):
                results.append(future.result())

        return results

    # ───────────────────────── email ─────────────────────────

    def _handle_email(self, email: str, lookup: set) -> list[dict]:
        results: list[dict] = []
        email = email.lower().strip()
        md5 = hashlib.md5(email.encode()).hexdigest()

        if self._wanted(lookup, "email"):
            try:
                r = self._client.get(f"https://www.gravatar.com/avatar/{md5}?d=404&s=1", timeout=10)
                results.append({
                    "category": "Email", "item": "Gravatar avatar",
                    "status": "found" if r.status_code == 200 else "not_found",
                    "detail": f"HTTP {r.status_code}",
                })
            except Exception as e:
                results.append({"category": "Email", "item": "Gravatar avatar", "status": "error", "detail": type(e).__name__})

            try:
                r = self._client.get(f"https://gravatar.com/{md5}.json", timeout=10)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        entry = data.get("entry", [{}])[0]
                        results.append({
                            "category": "Email", "item": "Gravatar profile",
                            "status": "found",
                            "detail": f"displayName={entry.get('displayName', '?')} profileUrl={entry.get('profileUrl', '?')}",
                        })
                    except Exception:
                        results.append({"category": "Email", "item": "Gravatar profile", "status": "found", "detail": "Public profile JSON available"})
                else:
                    results.append({"category": "Email", "item": "Gravatar profile", "status": "not_found", "detail": f"HTTP {r.status_code}"})
            except Exception as e:
                results.append({"category": "Email", "item": "Gravatar profile", "status": "error", "detail": type(e).__name__})

            key = self.get_option("HIBP_API_KEY")
            if key:
                try:
                    r = self._client.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(email)}?truncateResponse=false",
                        headers={"hibp-api-key": key},
                        timeout=15,
                    )
                    if r.status_code == 200:
                        breaches = [b.get("Name", "?") for b in r.json()]
                        results.append({"category": "Email", "item": "HIBP breaches", "status": "found", "detail": ", ".join(breaches)})
                    elif r.status_code == 404:
                        results.append({"category": "Email", "item": "HIBP breaches", "status": "not_found", "detail": "No breaches in HIBP"})
                    else:
                        results.append({"category": "Email", "item": "HIBP breaches", "status": "unknown", "detail": f"HTTP {r.status_code}"})
                except Exception as e:
                    results.append({"category": "Email", "item": "HIBP breaches", "status": "error", "detail": type(e).__name__})
            else:
                results.append({
                    "category": "Email", "item": "HIBP breaches",
                    "status": "unknown",
                    "detail": "Set HIBP_API_KEY to query haveibeenpwned.com",
                })

        local = email.split("@")[0]

        if self._wanted(lookup, "username"):
            console.print(f"  [cyan]>[/] Checking derived username [bold]{local}[/] across platforms...")
            for f in self._handle_username(local, {"username"}):
                f["category"] = "Username"
                results.append(f)

        return results

    # ───────────────────────── phone ─────────────────────────

    def _handle_phone(self, raw: str, lookup: set) -> list[dict]:
        results: list[dict] = []
        if not self._wanted(lookup, "phone"):
            return results

        try:
            import phonenumbers
            from phonenumbers import geocoder

            region = self.get_option("COUNTRY") or "US"
            num = phonenumbers.parse(raw, region)
            if phonenumbers.is_valid_number(num):
                e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
                national = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
                country = phonenumbers.region_code_for_number(num)
                number_type = phonenumbers.number_type(num)
                type_name = {
                    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                    phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
                    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
                    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
                    phonenumbers.PhoneNumberType.VOIP: "VoIP",
                }.get(number_type, "Unknown")
                geo = geocoder.description_for_number(num, "en")
                results.append({
                    "category": "Phone", "item": "Number parsed", "status": "found",
                    "detail": f"E.164={e164} | National={national} | Country={country} | Type={type_name} | Region={geo}",
                })
            else:
                results.append({"category": "Phone", "item": "Number", "status": "unknown", "detail": "Could not validate as a real number"})
        except Exception as e:
            results.append({"category": "Phone", "item": "Number", "status": "unknown", "detail": f"Parse error: {type(e).__name__}"})

        return results

    # ───────────────────────── photo ─────────────────────────

    def _handle_photo(self, path: str, lookup: set) -> list[dict]:
        results: list[dict] = []

        if self._wanted(lookup, "photo"):
            self._exif_and_hash(path, results)
            self._reverse_search(path, results)
            photo_dir = self.get_option("PHOTO_DIR")
            if photo_dir:
                self._face_match(path, photo_dir, results)
            else:
                results.append({
                    "category": "Photo", "item": "Local face match",
                    "status": "unknown", "detail": "Set PHOTO_DIR to enable local face matching",
                })

        return results

    def _exif_and_hash(self, path: str, results: list[dict]) -> None:
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
        except ImportError:
            results.append({"category": "Photo", "item": "EXIF", "status": "error", "detail": "PIL not available"})
            return

        try:
            img = Image.open(path)
            results.append({
                "category": "Photo", "item": "File",
                "status": "found",
                "detail": f"{os.path.basename(path)} | {img.width}x{img.height} | {img.format}",
            })
            exif = img.getexif()
            if not exif:
                results.append({"category": "Photo", "item": "EXIF", "status": "not_found", "detail": "No EXIF metadata"})
            else:
                tags = {}
                for tag_id, value in exif.items():
                    name = TAGS.get(tag_id, tag_id)
                    if isinstance(value, (bytes, bytearray)):
                        continue
                    if name == "GPSInfo":
                        gps = {}
                        for gtag_id, gval in value.items():
                            gps[GPSTAGS.get(gtag_id, gtag_id)] = gval
                        tags["GPS"] = self._format_gps(gps)
                    else:
                        tags[name] = str(value)[:80]
                detail = " | ".join(f"{k}={v}" for k, v in list(tags.items())[:12])
                results.append({"category": "Photo", "item": "EXIF", "status": "found", "detail": detail})
        except Exception as e:
            results.append({"category": "Photo", "item": "EXIF", "status": "error", "detail": type(e).__name__})

        try:
            import imagehash
            h = imagehash.phash(Image.open(path))
            dh = imagehash.dhash(Image.open(path))
            results.append({
                "category": "Photo", "item": "Hashes",
                "status": "found",
                "detail": f"phash={h} dhash={dh}",
            })
        except Exception as e:
            results.append({"category": "Photo", "item": "Hashes", "status": "error", "detail": type(e).__name__})

    @staticmethod
    def _format_gps(gps: dict) -> str:
        def to_deg(val):
            if isinstance(val, tuple) and len(val) == 3:
                return val[0] + val[1] / 60.0 + val[2] / 3600.0
            return None

        lat = to_deg(gps.get("GPSLatitude"))
        lon = to_deg(gps.get("GPSLongitude"))
        if lat is None or lon is None:
            return "present (no coordinates)"
        lat_ref = gps.get("GPSLatitudeRef", "N")
        lon_ref = gps.get("GPSLongitudeRef", "E")
        if isinstance(lat_ref, bytes):
            lat_ref = lat_ref.decode()
        if isinstance(lon_ref, bytes):
            lon_ref = lon_ref.decode()
        if lat_ref in ("S", "s"):
            lat = -lat
        if lon_ref in ("W", "w"):
            lon = -lon
        return f"{lat:.6f},{lon:.6f} https://maps.google.com/?q={lat:.6f},{lon:.6f}"

    def _reverse_search(self, path: str, results: list[dict]) -> None:
        photo_url = self.get_option("PHOTO_URL")
        if not photo_url:
            results.append({
                "category": "Photo", "item": "Reverse image search",
                "status": "unknown",
                "detail": "Set PHOTO_URL to a hosted copy, or search manually: lens.google.com | images.yandex.com | tineye.com",
            })
            return

        links = [
            ("Google Lens", f"https://lens.google.com/uploadbyurl?url={quote_plus(photo_url)}"),
            ("Yandex", f"https://yandex.com/images/search?rpt=imageview&url={quote_plus(photo_url)}"),
            ("Bing", f"https://www.bing.com/images/search?q=imgurl:{quote_plus(photo_url)}"),
            ("TinEye", f"https://tineye.com/search?url={quote_plus(photo_url)}"),
        ]
        results.append({
            "category": "Photo", "item": "Reverse image search",
            "status": "found",
            "detail": " | ".join(f"{name}: {url}" for name, url in links),
        })

    def _face_match(self, input_path: str, photo_dir: str, results: list[dict]) -> None:
        try:
            import cv2
        except ImportError:
            results.append({"category": "Photo", "item": "Face match", "status": "error", "detail": "opencv not available"})
            return

        if not (os.path.exists(YUNET_PATH) and os.path.exists(SFACE_PATH)):
            results.append({"category": "Photo", "item": "Face match", "status": "error", "detail": "YuNet/SFace models missing in webforg/data/opencv"})
            return

        try:
            detector = cv2.FaceDetectorYN.create(YUNET_PATH, "", (320, 320), score_threshold=0.6)
            recognizer = cv2.FaceRecognizerSF.create(SFACE_PATH, "")
        except Exception as e:
            results.append({"category": "Photo", "item": "Face match", "status": "error", "detail": type(e).__name__})
            return

        def embed(path):
            img = cv2.imread(path)
            if img is None:
                return None, []
            detector.setInputSize((img.shape[1], img.shape[0]))
            faces = detector.detect(img)[1]
            feats = []
            if faces is not None:
                for face in faces:
                    aligned = recognizer.alignCrop(img, face)
                    feats.append(recognizer.feature(aligned))
            return img, feats

        try:
            _, src_feats = embed(input_path)
            if not src_feats:
                results.append({"category": "Photo", "item": "Face match", "status": "not_found", "detail": "No face detected in input"})
                return

            matches = []
            for root, _dirs, files in os.walk(photo_dir):
                for fname in sorted(files):
                    if not fname.lower().endswith((".jpg", ".jpeg", ".png", ".webp", ".bmp")):
                        continue
                    fpath = os.path.join(root, fname)
                    if os.path.abspath(fpath) == os.path.abspath(input_path):
                        continue
                    try:
                        _, feats = embed(fpath)
                    except Exception:
                        continue
                    for feat in feats:
                        for sfeat in src_feats:
                            sim = float(recognizer.match(sfeat, feat, cv2.FaceRecognizerSF_FR_COSINE))
                            dist = float(recognizer.match(sfeat, feat, cv2.FaceRecognizerSF_FR_NORM_L2))
                            matches.append({"file": fname, "similarity": sim, "l2": dist})

            if matches:
                matches.sort(key=lambda m: -m["similarity"])
                for m in matches[:5]:
                    level = "MATCH" if m["similarity"] >= 0.55 else ("SIMILAR" if m["similarity"] >= 0.45 else "weak")
                    results.append({
                        "category": "Photo", "item": f"Face match in {m['file']}",
                        "status": "found" if level != "weak" else "unknown",
                        "detail": f"{level} | similarity={m['similarity']:.3f} | L2={m['l2']:.3f}",
                    })
            else:
                results.append({"category": "Photo", "item": "Face match", "status": "not_found", "detail": f"No faces matched in {photo_dir}"})
        except Exception as e:
            results.append({"category": "Photo", "item": "Face match", "status": "error", "detail": type(e).__name__})

    # ───────────────────────── report ─────────────────────────

    def _print_report(self, vector: str, input_value: str, findings: list[dict]) -> None:
        console.print()
        console.print(f"  [bold green]>[/] OSINT Identity — [bold]{input_value}[/]  (vector: [cyan]{vector}[/])")
        console.print()

        if not findings:
            console.print("  [yellow]No checks produced results.[/]")
            return

        status_style = {
            "found": "[bold red]FOUND[/]",
            "not_found": "[green]not found[/]",
            "unknown": "[yellow]unknown[/]",
            "error": "[bold yellow]error[/]",
        }

        from rich import box as rich_box

        table = Table(title="Findings", box=rich_box.ROUNDED, pad_edge=False)
        table.add_column("Category", style="bold cyan", width=18, overflow="fold")
        table.add_column("Item", style="white", width=26, overflow="fold")
        table.add_column("Status", width=12)
        table.add_column("Detail", style="dim", overflow="fold")

        for f in findings:
            table.add_row(
                f.get("category", ""),
                f.get("item", ""),
                status_style.get(f.get("status"), f.get("status", "")),
                f.get("detail", "")[:120],
            )

        console.print(table)

        found = sum(1 for f in findings if f.get("status") == "found")
        console.print(Panel(f"[bold]Found items: {found}[/]  |  Total checks: {len(findings)}", border_style="bold green"))
