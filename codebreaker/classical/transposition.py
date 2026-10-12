"""Transposition ciphers: rail fence and columnar."""

from __future__ import annotations

import itertools
from typing import List

from ..core import Candidate
from ..scoring import confidence, fitness


# ----------------------------- rail fence --------------------------------
def rail_encrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join("".join(r) for r in fence)


def rail_decrypt(text: str, rails: int) -> str:
    if rails < 2:
        return text
    n = len(text)
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    counts = [pattern.count(r) for r in range(rails)]
    slices, idx = [], 0
    for c in counts:
        slices.append(list(text[idx:idx + c]))
        idx += c
    pos = [0] * rails
    out = []
    for r in pattern:
        out.append(slices[r][pos[r]])
        pos[r] += 1
    return "".join(out)


def solve_railfence(ciphertext: str, max_rails: int = 12,
                    top: int = 3) -> List[Candidate]:
    cands: List[Candidate] = []
    for rails in range(2, min(max_rails, len(ciphertext)) + 1):
        pt = rail_decrypt(ciphertext, rails)
        cands.append(Candidate(
            score=fitness(pt), cipher="railfence", plaintext=pt, key=rails,
            confidence=confidence(pt), meta={"rails": rails}))
    cands.sort(reverse=True)
    return cands[:top]


# ----------------------------- columnar ----------------------------------
def columnar_decrypt(ciphertext: str, order: List[int]) -> str:
    """Decrypt a columnar transposition given the column read order.

    ``order`` is the permutation of column indices (0-based) in the order the
    columns were read out during encryption.
    """
    n = len(ciphertext)
    cols = len(order)
    rows = -(-n // cols)  # ceil
    num_full = n % cols or cols  # columns that have the extra row filled
    # Determine height of each original column.
    col_len = {}
    for c in range(cols):
        col_len[c] = rows if c < num_full else rows - 1
    # Read columns off the ciphertext in the given order.
    chunks = {}
    idx = 0
    for c in order:
        length = col_len[c]
        chunks[c] = ciphertext[idx:idx + length]
        idx += length
    # Reassemble row by row.
    out = []
    pointers = {c: 0 for c in range(cols)}
    for _ in range(rows):
        for c in range(cols):
            if pointers[c] < len(chunks.get(c, "")):
                out.append(chunks[c][pointers[c]])
                pointers[c] += 1
    return "".join(out)


def solve_columnar(ciphertext: str, max_cols: int = 7,
                   top: int = 3) -> List[Candidate]:
    """Brute-force small columnar transpositions by trying all column orders.

    Factorial growth means we cap at ``max_cols`` (7 => 5040 perms/width).
    """
    cands: List[Candidate] = []
    for cols in range(2, max_cols + 1):
        if cols > len(ciphertext):
            break
        for order in itertools.permutations(range(cols)):
            pt = columnar_decrypt(ciphertext, list(order))
            cands.append(Candidate(
                score=fitness(pt), cipher="columnar", plaintext=pt,
                key=list(order), confidence=confidence(pt),
                meta={"columns": cols, "order": list(order)}))
    cands.sort(reverse=True)
    # Deduplicate identical plaintexts.
    seen, out = set(), []
    for c in cands:
        if c.plaintext in seen:
            continue
        seen.add(c.plaintext)
        out.append(c)
        if len(out) >= top:
            break
    return out
