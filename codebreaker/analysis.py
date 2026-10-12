"""Statistical analysis primitives for cryptanalysis.

These are the measurements a human cryptanalyst reaches for first:
letter-frequency profiles, the index of coincidence (to tell mono- from
poly-alphabetic ciphers and to estimate key length), Kasiski examination,
and Shannon entropy (to flag compressed/encrypted/random data).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, List, Tuple

from .scoring import clean

ENGLISH_IOC = 0.0667  # expected IoC of English text
RANDOM_IOC = 1.0 / 26


def frequency(text: str) -> Dict[str, float]:
    """Relative letter frequencies (0..1) over A-Z."""
    t = clean(text)
    n = len(t)
    counts = Counter(t)
    return {c: counts.get(c, 0) / n for c in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"} if n else {}


def index_of_coincidence(text: str) -> float:
    """Index of coincidence.  ~0.067 English, ~0.038 random/polyalphabetic."""
    t = clean(text)
    n = len(t)
    if n < 2:
        return 0.0
    counts = Counter(t)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8).  ~8.0 => random/encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def estimate_key_length_ioc(text: str, max_len: int = 20) -> List[Tuple[int, float]]:
    """Estimate polyalphabetic key length by average per-column IoC.

    Returns ``(length, avg_ioc)`` pairs sorted by closeness to English IoC.
    """
    t = clean(text)
    results = []
    for k in range(1, min(max_len, len(t)) + 1):
        cols = ["".join(t[i::k]) for i in range(k)]
        iocs = [index_of_coincidence(c) for c in cols if len(c) >= 2]
        if iocs:
            results.append((k, sum(iocs) / len(iocs)))
    results.sort(key=lambda kv: abs(kv[1] - ENGLISH_IOC))
    return results


def kasiski_examination(text: str, seq_len: int = 3,
                        max_len: int = 20) -> List[Tuple[int, int]]:
    """Kasiski test: find spacings between repeated substrings and score
    candidate key lengths by how many spacings they divide.

    Returns ``(length, votes)`` sorted by votes descending.
    """
    t = clean(text)
    positions: Dict[str, List[int]] = {}
    for i in range(len(t) - seq_len + 1):
        positions.setdefault(t[i:i + seq_len], []).append(i)

    spacings: List[int] = []
    for pos in positions.values():
        if len(pos) > 1:
            for a, b in zip(pos, pos[1:]):
                spacings.append(b - a)

    votes = Counter()
    for k in range(2, max_len + 1):
        for s in spacings:
            if s % k == 0:
                votes[k] += 1
    return votes.most_common()


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (rough text detector)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(data)
