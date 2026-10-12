"""XOR ciphers: single-byte and repeating-key.

The repeating-key attack is the classic one: find the key size via normalised
Hamming distance, then solve each key-byte independently as a single-byte XOR
scored by English letter plausibility.
"""

from __future__ import annotations

from typing import List, Tuple

from ..core import Candidate
from ..scoring import MONOGRAM_PCT

# Character scoring table for raw bytes: reward common English letters/space.
_CHAR_SCORE = {}
for _c, _v in MONOGRAM_PCT.items():
    _CHAR_SCORE[ord(_c)] = _v            # upper-case
    _CHAR_SCORE[ord(_c.lower())] = _v    # lower-case
_CHAR_SCORE[ord(" ")] = 13.0  # space is the most common character in English


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _english_byte_score(data: bytes) -> float:
    score = 0.0
    for b in data:
        if b == 0 or b > 126:
            score -= 5.0
        else:
            score += _CHAR_SCORE.get(b, 0.0)
            if b in (9, 10, 13) or 32 <= b <= 126:
                score += 0.3
    return score / max(1, len(data))


def solve_single_byte(data: bytes, top: int = 3) -> List[Candidate]:
    cands: List[Candidate] = []
    for k in range(256):
        dec = xor_bytes(data, bytes([k]))
        sc = _english_byte_score(dec)
        try:
            text = dec.decode("utf-8")
        except UnicodeDecodeError:
            text = dec.decode("latin-1")
        cands.append(Candidate(
            score=sc, cipher="xor-single", plaintext=text, key=k,
            confidence=max(0.0, min(1.0, sc / 6.0)),
            meta={"key_byte": k, "key_hex": f"{k:02x}"},
        ))
    cands.sort(reverse=True)
    return cands[:top]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_key_sizes(data: bytes, min_size: int = 2, max_size: int = 40,
                    top: int = 4) -> List[Tuple[int, float]]:
    results = []
    for ks in range(min_size, min(max_size, len(data) // 2) + 1):
        blocks = [data[i:i + ks] for i in range(0, ks * 4, ks)
                  if len(data[i:i + ks]) == ks]
        if len(blocks) < 2:
            continue
        dists = [_hamming(blocks[i], blocks[i + 1]) / ks
                 for i in range(len(blocks) - 1)]
        results.append((ks, sum(dists) / len(dists)))
    results.sort(key=lambda kv: kv[1])
    return results[:top]


def solve_repeating_key(data: bytes, min_size: int = 2, max_size: int = 40,
                        top: int = 3) -> List[Candidate]:
    cands: List[Candidate] = []
    for ks, _ in guess_key_sizes(data, min_size, max_size):
        key = bytearray()
        for i in range(ks):
            column = data[i::ks]
            best = solve_single_byte(column, top=1)
            key.append(best[0].key if best else 0)
        dec = xor_bytes(data, bytes(key))
        sc = _english_byte_score(dec)
        try:
            text = dec.decode("utf-8")
        except UnicodeDecodeError:
            text = dec.decode("latin-1")
        cands.append(Candidate(
            score=sc, cipher="xor-repeating", plaintext=text, key=bytes(key),
            confidence=max(0.0, min(1.0, sc / 6.0)),
            meta={"key_size": ks, "key_hex": bytes(key).hex(),
                  "key_ascii": bytes(key).decode("latin-1", "replace")},
        ))
    cands.sort(reverse=True)
    return cands[:top]
