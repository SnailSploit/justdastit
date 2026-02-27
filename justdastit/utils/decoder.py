"""justdastit - Decoder utility for encoding/decoding/hashing."""

from __future__ import annotations

__all__ = [
    "DECODERS",
    "ENCODERS",
    "HASHERS",
    "smart_decode",
    "jwt_decode",
    "url_encode",
    "url_decode",
    "base64_encode",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "html_encode",
    "html_decode",
    "md5",
    "sha1",
    "sha256",
    "sha512",
]

import base64
import hashlib
import html
import json
import urllib.parse
from typing import Optional


def url_encode(data: str, full: bool = False) -> str:
    if full:
        return urllib.parse.quote(data, safe="")
    return urllib.parse.quote(data)


def url_decode(data: str) -> str:
    return urllib.parse.unquote(data)


def double_url_encode(data: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(data, safe=""), safe="")


def base64_encode(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


def base64_decode(data: str) -> str:
    # Handle missing padding
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data).decode("utf-8", errors="replace")


def base64url_encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def base64url_decode(data: str) -> str:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")


def html_encode(data: str) -> str:
    return html.escape(data)


def html_decode(data: str) -> str:
    return html.unescape(data)


def hex_encode(data: str) -> str:
    return data.encode().hex()


def hex_decode(data: str) -> str:
    return bytes.fromhex(data).decode("utf-8", errors="replace")


def unicode_escape(data: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in data)


def unicode_unescape(data: str) -> str:
    return data.encode().decode("unicode_escape")


def json_encode(data: str) -> str:
    return json.dumps(data)


def json_decode(data: str) -> str:
    return json.loads(data)


# Hash functions
def md5(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()


def sha1(data: str) -> str:
    return hashlib.sha1(data.encode()).hexdigest()


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def sha512(data: str) -> str:
    return hashlib.sha512(data.encode()).hexdigest()


def jwt_decode(token: str) -> dict:
    """Decode a JWT token (without verification)."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")

    result = {}
    try:
        result["header"] = json.loads(base64url_decode(parts[0]))
    except Exception as e:
        result["header_error"] = str(e)
    try:
        result["payload"] = json.loads(base64url_decode(parts[1]))
    except Exception as e:
        result["payload_error"] = str(e)
    if len(parts) > 2:
        result["signature"] = parts[2]

    return result


# Registry for CLI access
ENCODERS = {
    "url": url_encode,
    "url-full": lambda d: url_encode(d, full=True),
    "double-url": double_url_encode,
    "b64": base64_encode,
    "b64url": base64url_encode,
    "html": html_encode,
    "hex": hex_encode,
    "unicode": unicode_escape,
    "json": json_encode,
}

DECODERS = {
    "url": url_decode,
    "b64": base64_decode,
    "b64url": base64url_decode,
    "html": html_decode,
    "hex": hex_decode,
    "unicode": unicode_unescape,
    "json": json_decode,
    "jwt": lambda t: json.dumps(jwt_decode(t), indent=2),
}

HASHERS = {
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "sha512": sha512,
}


def smart_decode(data: str) -> list[tuple[str, str]]:
    """Try all decoders and return successful results."""
    results: list[tuple[str, str]] = []
    for name, func in DECODERS.items():
        try:
            decoded = func(data)
            if decoded != data and decoded:
                results.append((name, str(decoded)))
        except Exception:
            pass
    return results
