"""Letter-name / homophone ("rebus") reading.

A different model again: read each letter and digit as the WORD it sounds like
when spoken aloud — C = "see", U = "you", R = "are", 2 = "to", 4 = "for",
8 = "ate" — the way people write "CU" for "see you".  This is aimed squarely
at the one unit every other method failed on: the recurring ``NCBE`` refrain.

For each token it generates the possible spoken readings, concatenates them,
and scores how English-like the result is.  It reports the best readings as
hypotheses.  If a token (like NCBE) has no coherent letter-name reading, that
is reported too — the tool does not force a false answer.
"""

from __future__ import annotations

from itertools import product
from typing import Dict, List, Tuple

from .scoring import confidence, word_coverage

# Letter -> words it can sound like (spoken letter-name and common homophones).
HOMOPHONES: Dict[str, List[str]] = {
    "A": ["a"], "B": ["be", "bee"], "C": ["see", "sea"], "D": ["dee"],
    "E": ["e"], "F": ["ef"], "G": ["gee"], "H": ["aych"], "I": ["i", "eye"],
    "J": ["jay"], "K": ["kay"], "L": ["el"], "M": ["em"], "N": ["en", "and"],
    "O": ["oh", "owe"], "P": ["pee", "pea"], "Q": ["cue", "queue"],
    "R": ["are"], "S": ["es"], "T": ["tee", "tea"], "U": ["you"],
    "V": ["vee"], "W": ["double u"], "X": ["ex"], "Y": ["why"], "Z": ["zee"],
    "0": ["zero", "oh"], "1": ["one", "won"], "2": ["to", "too", "two"],
    "3": ["three"], "4": ["for", "four"], "5": ["five"], "6": ["six"],
    "7": ["seven"], "8": ["ate", "eight"], "9": ["nine"],
}

_MAX_LEN = 6         # rebus reading only makes sense for short tokens
_MAX_COMBOS = 6000


def readings(token: str, limit: int = 5) -> List[Tuple[str, float]]:
    """Return scored spoken readings of ``token`` (best first).

    Each reading is the concatenation of one homophone per character.  Scoring
    rewards readings that contain real English words.  Empty if the token is
    too long or has characters with no homophone.
    """
    token = token.upper()
    if not (1 <= len(token) <= _MAX_LEN):
        return []
    options = []
    for ch in token:
        opts = HOMOPHONES.get(ch)
        if not opts:
            return []
        options.append(opts)
    total = 1
    for o in options:
        total *= len(o)
    if total > _MAX_COMBOS:
        return []

    scored = []
    for combo in product(*options):
        spaced = " ".join(combo)          # e.g. "see you"
        joined = "".join(combo)           # e.g. "seeyou"
        # Score the spaced form by dictionary word coverage, and the joined
        # form by overall english-ness; take the better signal.
        score = max(word_coverage(spaced), confidence(joined))
        scored.append((spaced, round(score, 3)))
    scored.sort(key=lambda s: s[1], reverse=True)
    # Deduplicate.
    seen, out = set(), []
    for s, sc in scored:
        if s in seen:
            continue
        seen.add(s)
        out.append((s, sc))
        if len(out) >= limit:
            break
    return out


def best_reading(token: str) -> Tuple[str, float]:
    r = readings(token, limit=1)
    return r[0] if r else ("", 0.0)
