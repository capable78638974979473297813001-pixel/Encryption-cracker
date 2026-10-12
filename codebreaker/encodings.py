"""Reversible encodings (not encryption) and a recursive auto-decoder.

A huge fraction of "mystery strings" in CTFs and logs are just layered
encodings (base64 of hex of ...).  ``recursive_decode`` peels them.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from typing import List, Optional, Tuple

from .analysis import printable_ratio


def _try(fn) -> Optional[bytes]:
    try:
        return fn()
    except Exception:
        return None


def decode_base64(s: str) -> Optional[bytes]:
    s2 = s.strip().replace("\n", "")
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", s2) or len(s2) < 4:
        return None
    pad = (-len(s2)) % 4
    return _try(lambda: base64.b64decode(s2 + "=" * pad, validate=False))


def decode_base64url(s: str) -> Optional[bytes]:
    s2 = s.strip().replace("\n", "")
    if not re.fullmatch(r"[A-Za-z0-9_\-=]+", s2) or len(s2) < 4:
        return None
    pad = (-len(s2)) % 4
    return _try(lambda: base64.urlsafe_b64decode(s2 + "=" * pad))


def decode_base32(s: str) -> Optional[bytes]:
    s2 = s.strip().upper().replace("\n", "")
    if not re.fullmatch(r"[A-Z2-7=]+", s2) or len(s2) < 8:
        return None
    pad = (-len(s2)) % 8
    return _try(lambda: base64.b32decode(s2 + "=" * pad))


def decode_hex(s: str) -> Optional[bytes]:
    s2 = re.sub(r"[\s:]", "", s.strip())
    if not re.fullmatch(r"(0x)?[0-9a-fA-F]+", s2) or len(s2) < 2:
        return None
    s2 = s2[2:] if s2.lower().startswith("0x") else s2
    if len(s2) % 2:
        return None
    return _try(lambda: bytes.fromhex(s2))


def decode_binary(s: str) -> Optional[bytes]:
    bits = re.sub(r"\s", "", s.strip())
    if not re.fullmatch(r"[01]+", bits) or len(bits) < 8 or len(bits) % 8:
        return None
    return _try(lambda: bytes(int(bits[i:i + 8], 2)
                              for i in range(0, len(bits), 8)))


def decode_decimal(s: str) -> Optional[bytes]:
    parts = re.split(r"[\s,]+", s.strip())
    if len(parts) < 2 or not all(p.isdigit() for p in parts):
        return None
    if any(int(p) > 255 for p in parts):
        return None
    return _try(lambda: bytes(int(p) for p in parts))


def decode_url(s: str) -> Optional[bytes]:
    if "%" not in s:
        return None
    return _try(lambda: urllib.parse.unquote_plus(s).encode("utf-8", "replace"))


def decode_rot13(s: str) -> Optional[bytes]:
    if not re.search(r"[A-Za-z]", s):
        return None
    return codecs.encode(s, "rot_13").encode("utf-8", "replace")


DECODERS = [
    ("base64", decode_base64),
    ("base64url", decode_base64url),
    ("base32", decode_base32),
    ("hex", decode_hex),
    ("binary", decode_binary),
    ("decimal", decode_decimal),
    ("url", decode_url),
]


def _looks_textual(data: bytes) -> bool:
    return printable_ratio(data) > 0.90


def recursive_decode(s: str, max_depth: int = 8) -> Tuple[str, List[str]]:
    """Peel layered encodings until the result looks like plain text.

    Returns ``(decoded_text, steps)`` where ``steps`` names each layer applied.
    """
    current = s.strip()
    steps: List[str] = []
    for _ in range(max_depth):
        progressed = False
        for name, dec in DECODERS:
            out = dec(current)
            if out is None:
                continue
            # Avoid trivial/no-op transforms.
            try:
                as_text = out.decode("utf-8")
            except UnicodeDecodeError:
                as_text = out.decode("latin-1")
            if as_text == current or not out:
                continue
            if _looks_textual(out):
                steps.append(name)
                current = as_text
                progressed = True
                break
        if not progressed:
            break
    return current, steps
