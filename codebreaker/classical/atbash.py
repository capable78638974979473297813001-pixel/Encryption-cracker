"""Atbash cipher: reverse the alphabet (A<->Z).  Self-inverse."""

from __future__ import annotations

from typing import List

from ..core import Candidate
from ..scoring import confidence, fitness


def encrypt(text: str) -> str:
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr(90 - (ord(ch) - 65)))
        elif ch.islower():
            out.append(chr(122 - (ord(ch) - 97)))
        else:
            out.append(ch)
    return "".join(out)


decrypt = encrypt  # self-inverse


def solve(ciphertext: str, top: int = 1) -> List[Candidate]:
    pt = decrypt(ciphertext)
    return [Candidate(
        score=fitness(pt),
        cipher="atbash",
        plaintext=pt,
        key="atbash",
        confidence=confidence(pt),
    )]
