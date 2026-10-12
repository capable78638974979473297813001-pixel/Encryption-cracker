"""Caesar / ROT-N shift cipher: encrypt, decrypt, and brute-force solve."""

from __future__ import annotations

from typing import List

from ..core import Candidate
from ..scoring import chi_squared, confidence


def _shift_char(ch: str, n: int) -> str:
    if ch.isupper():
        return chr((ord(ch) - 65 + n) % 26 + 65)
    if ch.islower():
        return chr((ord(ch) - 97 + n) % 26 + 97)
    return ch


def encrypt(text: str, shift: int) -> str:
    return "".join(_shift_char(c, shift) for c in text)


def decrypt(text: str, shift: int) -> str:
    return encrypt(text, -shift)


def solve(ciphertext: str, top: int = 3) -> List[Candidate]:
    """Try all 26 shifts; rank by chi-squared fit to English."""
    cands: List[Candidate] = []
    for shift in range(26):
        pt = decrypt(ciphertext, shift)
        chi = chi_squared(pt)
        cands.append(Candidate(
            score=-chi,                 # lower chi is better -> negate
            cipher="caesar",
            plaintext=pt,
            key=shift,
            confidence=confidence(pt),
            meta={"shift": shift, "chi_squared": round(chi, 2)},
        ))
    cands.sort(reverse=True)
    return cands[:top]
