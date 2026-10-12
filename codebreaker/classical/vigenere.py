"""Vigenere cipher: encrypt, decrypt, and automated key recovery.

Strategy:
  1. Estimate likely key lengths (index of coincidence + Kasiski votes).
  2. For each candidate length, recover the key one column at a time by
     choosing the shift that best fits English letter frequencies.
  3. Rank full decryptions by the English-fitness model and return the best.
"""

from __future__ import annotations

from typing import List, Optional

from ..analysis import (ENGLISH_IOC, estimate_key_length_ioc,
                        kasiski_examination)
from ..core import Candidate
from ..scoring import MONOGRAM_PCT, clean, confidence, fitness

_FREQ = [MONOGRAM_PCT[c] / 100.0 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]


def _key_to_shifts(key: str) -> List[int]:
    return [ord(k) - 65 for k in clean(key)]


def encrypt(text: str, key: str) -> str:
    shifts = _key_to_shifts(key)
    if not shifts:
        raise ValueError("empty key")
    out, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            s = shifts[j % len(shifts)]
            out.append(chr((ord(ch) - base + s) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def decrypt(text: str, key: str) -> str:
    shifts = _key_to_shifts(key)
    if not shifts:
        raise ValueError("empty key")
    out, j = [], 0
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            s = shifts[j % len(shifts)]
            out.append(chr((ord(ch) - base - s) % 26 + base))
            j += 1
        else:
            out.append(ch)
    return "".join(out)


def _best_shift_for_column(col: str) -> int:
    """Pick the shift whose decrypted column best matches English freq
    (maximises the correlation with expected letter frequencies)."""
    best_shift, best_corr = 0, -1.0
    n = len(col)
    counts = [col.count(chr(65 + i)) for i in range(26)]
    for s in range(26):
        corr = sum(counts[(i + s) % 26] / n * _FREQ[i] for i in range(26))
        if corr > best_corr:
            best_corr, best_shift = corr, s
    return best_shift


def recover_key(ciphertext: str, key_len: int) -> str:
    t = clean(ciphertext)
    key_chars = []
    for i in range(key_len):
        col = t[i::key_len]
        key_chars.append(chr(65 + _best_shift_for_column(col)))
    return "".join(key_chars)


def candidate_key_lengths(ciphertext: str, max_len: int = 20) -> List[int]:
    ioc = [k for k, _ in estimate_key_length_ioc(ciphertext, max_len)[:6]]
    kas = [k for k, _ in kasiski_examination(ciphertext, max_len=max_len)[:6]]
    ordered: List[int] = []
    for k in ioc + kas:
        if k not in ordered:
            ordered.append(k)
    return ordered or [1]


def solve(ciphertext: str, max_len: int = 20, top: int = 3,
          key_len: Optional[int] = None) -> List[Candidate]:
    lengths = [key_len] if key_len else candidate_key_lengths(ciphertext, max_len)
    cands: List[Candidate] = []
    seen = set()
    for L in lengths:
        if L < 1 or L in seen:
            continue
        seen.add(L)
        key = recover_key(ciphertext, L)
        pt = decrypt(ciphertext, key)
        cands.append(Candidate(
            score=fitness(pt),
            cipher="vigenere",
            plaintext=pt,
            key=key,
            confidence=confidence(pt),
            meta={"key_length": L, "key": key},
        ))
    cands.sort(reverse=True)
    return cands[:top]
