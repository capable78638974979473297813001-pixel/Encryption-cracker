"""Monoalphabetic substitution cipher solver.

Uses hill-climbing with random restarts over the fitness model (quadgram if
available, else bigram).  This is the standard, highly effective attack on
simple substitution ciphers given enough ciphertext (~80+ letters).
"""

from __future__ import annotations

import random
from typing import Dict, List, Optional

from ..core import Candidate
from ..scoring import clean, confidence, fitness, word_coverage

_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# The hill-climb objective blends n-gram fitness (a smooth gradient the search
# can follow) with dictionary word-coverage (which decisively rewards real
# English and pulls the search out of near-miss local optima).  Weight tuned
# empirically; see tests.
_WORD_WEIGHT = 6.0


def _objective(text: str) -> float:
    return fitness(text) + _WORD_WEIGHT * word_coverage(text)


def apply_key(text: str, key: str) -> str:
    """``key`` maps plaintext A-Z -> cipher letter at that index (a permutation).

    Decryption applies the inverse mapping to the ciphertext.
    """
    inv = {key[i]: _ALPHA[i] for i in range(26)}
    out = []
    for ch in text:
        up = ch.upper()
        if up in inv:
            dec = inv[up]
            out.append(dec if ch.isupper() else dec.lower())
        else:
            out.append(ch)
    return "".join(out)


def _freq_seed(ciphertext: str) -> str:
    """Seed key by matching cipher-letter frequency order to English order."""
    from collections import Counter
    english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    counts = Counter(clean(ciphertext))
    cipher_order = [c for c, _ in counts.most_common()]
    for c in _ALPHA:
        if c not in cipher_order:
            cipher_order.append(c)
    # Map most-common cipher letter -> E, etc.  Build plaintext->cipher key.
    mapping = {}
    for e_char, c_char in zip(english_order, cipher_order):
        mapping[e_char] = c_char
    return "".join(mapping.get(p, p) for p in _ALPHA)


def solve(ciphertext: str, restarts: int = 25, iterations: int = 2500,
          top: int = 3, seed: Optional[int] = None) -> List[Candidate]:
    rng = random.Random(seed)
    results: List[Candidate] = []

    seed_key = _freq_seed(ciphertext)

    for r in range(restarts):
        if r == 0:
            parent = list(seed_key)
        else:
            parent = list(_ALPHA)
            rng.shuffle(parent)
        parent_pt = apply_key(ciphertext, "".join(parent))
        parent_score = _objective(parent_pt)

        stale = 0
        for _ in range(iterations):
            i, j = rng.randrange(26), rng.randrange(26)
            if i == j:
                continue
            child = parent[:]
            child[i], child[j] = child[j], child[i]
            child_pt = apply_key(ciphertext, "".join(child))
            child_score = _objective(child_pt)
            if child_score > parent_score:
                parent, parent_score, parent_pt = child, child_score, child_pt
                stale = 0
            else:
                stale += 1
                if stale > 1000:          # converged; stop this restart early
                    break

        results.append(Candidate(
            score=parent_score,
            cipher="substitution",
            plaintext=parent_pt,
            key="".join(parent),
            confidence=confidence(parent_pt),
            meta={"restart": r},
        ))

    # Deduplicate by plaintext, keep best.
    best: Dict[str, Candidate] = {}
    for c in results:
        if c.plaintext not in best or c.score > best[c.plaintext].score:
            best[c.plaintext] = c
    out = sorted(best.values(), reverse=True)
    return out[:top]
