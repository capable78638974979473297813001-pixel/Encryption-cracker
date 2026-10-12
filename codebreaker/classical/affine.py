"""Affine cipher  E(x) = (a*x + b) mod 26,  with gcd(a,26)=1."""

from __future__ import annotations

from math import gcd
from typing import List

from ..core import Candidate
from ..scoring import chi_squared, confidence

_VALID_A = [a for a in range(1, 26) if gcd(a, 26) == 1]
_INV_A = {a: pow(a, -1, 26) for a in _VALID_A}


def _map_char(ch: str, fn) -> str:
    if ch.isupper():
        return chr(fn(ord(ch) - 65) % 26 + 65)
    if ch.islower():
        return chr(fn(ord(ch) - 97) % 26 + 97)
    return ch


def encrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("'a' must be coprime with 26")
    return "".join(_map_char(c, lambda x: a * x + b) for c in text)


def decrypt(text: str, a: int, b: int) -> str:
    inv = _INV_A[a]
    return "".join(_map_char(c, lambda x: inv * (x - b)) for c in text)


def solve(ciphertext: str, top: int = 3) -> List[Candidate]:
    cands: List[Candidate] = []
    for a in _VALID_A:
        for b in range(26):
            pt = decrypt(ciphertext, a, b)
            chi = chi_squared(pt)
            cands.append(Candidate(
                score=-chi,
                cipher="affine",
                plaintext=pt,
                key=(a, b),
                confidence=confidence(pt),
                meta={"a": a, "b": b, "chi_squared": round(chi, 2)},
            ))
    cands.sort(reverse=True)
    return cands[:top]
