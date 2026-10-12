"""Sound-based ("read it aloud") matching — a deliberately different lens.

The FBI's analysts attacked the McCormick notes as a cipher: letter
frequencies, pattern words, address lists.  That is a *spelling*-based view.
But the writer was, by his family's account, barely literate — which means he
likely wrote by SOUND, not by correct spelling.  Letter-exact methods cannot
see through that; phonetic matching can.

This module folds each token's consonants into sound classes (so B/P, C/K/Q,
S/Z, D/T, F/V, M/N collapse, H/Y drop) and matches against common English
words folded the same way.  It finds words a token could *sound like* even
when the letters differ from any correct spelling.

Measured on the McCormick transcription this roughly doubles the fraction of
tokens with a candidate match versus exact letter-skeleton matching, and
surfaces plausible sound-alikes (e.g. NPRSE~NUMBERS, CDNSE~ACTIONS) that a
spelling-based search misses.

Honesty note: looser matching matches MORE words by construction, so a high
coverage number is not a decoding.  The value is in the specific plausible
candidates, and the method still produces no verifiable plaintext.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from functools import lru_cache
from typing import Dict, List

_VOWELS = set("AEIOU")
_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "data", "common10k.txt")

# Consonant -> sound class.  Crude but principled: merge the pairs a speller
# most often confuses, drop the near-silent letters.
_FOLD = str.maketrans({
    "B": "P", "P": "P", "C": "K", "K": "K", "Q": "K", "G": "J", "J": "J",
    "S": "S", "Z": "S", "D": "T", "T": "T", "F": "F", "V": "F", "M": "N",
    "N": "N", "L": "L", "R": "R", "W": "W", "X": "K", "Y": "", "H": "",
})


def skeleton(word: str) -> str:
    return "".join(c for c in word.upper() if c.isalpha() and c not in _VOWELS)


def sound_key(token: str) -> str:
    """Fold a token to its consonant-sound key (adjacent duplicates merged)."""
    folded = skeleton(token).translate(_FOLD)
    out = []
    for c in folded:
        if not out or out[-1] != c:
            out.append(c)
    return "".join(out)


@lru_cache(maxsize=1)
def _words() -> List[str]:
    if not os.path.exists(_WORDLIST_PATH):
        from .data.words import COMMON_WORDS
        return sorted(COMMON_WORDS)
    with open(_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as fh:
        return [w.strip().upper() for w in fh if w.strip()]


@lru_cache(maxsize=1)
def _sound_index() -> Dict[str, List[str]]:
    index: Dict[str, List[str]] = defaultdict(list)
    for w in _words():
        if w.isalpha():
            index[sound_key(w)].append(w)   # words stay in frequency order
    return index


def _strip_terminal_e(token: str) -> str:
    t = token.upper()
    while t.endswith("E") and len(t) > 1:
        t = t[:-1]
    return t


def sound_matches(token: str, limit: int = 6) -> List[str]:
    """Common words that SOUND like ``token`` (after folding, -E stripped)."""
    key = sound_key(_strip_terminal_e(token))
    if not key:
        return []
    return _sound_index().get(key, [])[:limit]


_TOKEN_RE = re.compile(r"[A-Za-z]+")


def _tokens(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.extend(m.group(0).upper() for m in _TOKEN_RE.finditer(line))
    return out


def analyze(text: str) -> Dict:
    toks = _tokens(text)
    eligible = [t for t in toks if len(skeleton(t)) >= 3]
    matched = [t for t in eligible if sound_matches(t)]
    per_token = []
    for t in sorted(set(eligible), key=lambda x: (-toks.count(x), x)):
        m = sound_matches(t)
        if m:
            per_token.append({"token": t, "count": toks.count(t), "sounds": m})
    return {
        "eligible": len(eligible),
        "matched": len(matched),
        "coverage": len(matched) / len(eligible) if eligible else 0.0,
        "per_token": per_token,
    }
