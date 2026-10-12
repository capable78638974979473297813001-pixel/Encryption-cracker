"""English-language fitness scoring.

The heart of any classical-cipher breaker is a function that answers:
"how English-like is this text?"  We provide several complementary scorers:

* monogram chi-squared     -> fast, great for Caesar/affine key ranking
* bigram log-likelihood    -> robust, drives Vigenere/substitution search
* quadgram log-likelihood  -> gold standard, used automatically when a
                              quadgram model file is available (see
                              ``scripts/build_quadgrams.py``)
* dictionary word coverage -> excellent final-answer validator

The built-in bigram/monogram tables let the toolkit break real ciphers out
of the box with zero data files.  Pointing ``build-model`` at a large corpus
upgrades the engine to full quadgram fitness for maximum accuracy.
"""

from __future__ import annotations

import math
import os
import re
from functools import lru_cache
from typing import Dict, Iterable, Optional

# --------------------------------------------------------------------------
# English monogram frequencies (percent).  Source: large-corpus averages.
# --------------------------------------------------------------------------
MONOGRAM_PCT: Dict[str, float] = {
    "A": 8.167, "B": 1.492, "C": 2.782, "D": 4.253, "E": 12.702,
    "F": 2.228, "G": 2.015, "H": 6.094, "I": 6.966, "J": 0.153,
    "K": 0.772, "L": 4.025, "M": 2.406, "N": 6.749, "O": 7.507,
    "P": 1.929, "Q": 0.095, "R": 5.987, "S": 6.327, "T": 9.056,
    "U": 2.758, "V": 0.978, "W": 2.360, "X": 0.150, "Y": 1.974,
    "Z": 0.074,
}

# Top English bigrams with approximate relative frequency (percent of all
# bigrams).  Unlisted bigrams get a small floor so the scorer degrades
# gracefully rather than rejecting plausible text outright.
BIGRAM_PCT: Dict[str, float] = {
    "TH": 3.56, "HE": 3.07, "IN": 2.43, "ER": 2.05, "AN": 1.99,
    "RE": 1.85, "ON": 1.76, "AT": 1.49, "EN": 1.45, "ND": 1.35,
    "TI": 1.34, "ES": 1.34, "OR": 1.28, "TE": 1.20, "OF": 1.17,
    "ED": 1.17, "IS": 1.13, "IT": 1.12, "AL": 1.09, "AR": 1.07,
    "ST": 1.05, "TO": 1.04, "NT": 1.04, "NG": 0.95, "SE": 0.93,
    "HA": 0.93, "AS": 0.87, "OU": 0.87, "IO": 0.83, "LE": 0.83,
    "VE": 0.83, "CO": 0.79, "ME": 0.79, "DE": 0.76, "HI": 0.76,
    "RI": 0.73, "RO": 0.73, "IC": 0.70, "NE": 0.69, "EA": 0.69,
    "RA": 0.69, "CE": 0.65, "LI": 0.62, "CH": 0.60, "LL": 0.58,
    "BE": 0.58, "MA": 0.57, "SI": 0.55, "OM": 0.55, "UR": 0.54,
    "CA": 0.54, "EL": 0.53, "TA": 0.53, "LA": 0.53, "NS": 0.51,
    "DI": 0.50, "FO": 0.49, "HO": 0.46, "PE": 0.46, "EC": 0.45,
    "PR": 0.45, "NO": 0.44, "CT": 0.44, "US": 0.43, "AC": 0.43,
    "OT": 0.43, "IL": 0.43, "TR": 0.42, "LY": 0.42, "NC": 0.41,
    "ET": 0.41, "UT": 0.40, "SS": 0.40, "SO": 0.39, "RS": 0.39,
    "UN": 0.39, "LO": 0.38, "WA": 0.38, "GE": 0.37, "IE": 0.37,
    "WH": 0.37, "EE": 0.37, "WI": 0.36, "EM": 0.36, "AD": 0.35,
    "OL": 0.34, "RT": 0.34, "PO": 0.34, "WE": 0.33, "NA": 0.33,
    "UL": 0.33, "NI": 0.33, "TS": 0.33, "MO": 0.32, "OW": 0.33,
    "PA": 0.32, "IM": 0.32, "MI": 0.32, "AI": 0.31, "SH": 0.31,
    "IR": 0.31, "SU": 0.31, "ID": 0.30, "OS": 0.30, "IV": 0.30,
    "IA": 0.30, "AM": 0.29, "FI": 0.29, "CI": 0.29, "VI": 0.27,
    "PL": 0.27, "IG": 0.26, "TU": 0.26, "EV": 0.26, "LD": 0.25,
    "RY": 0.25, "MP": 0.24, "FE": 0.24, "BL": 0.24, "AB": 0.23,
    "GH": 0.23, "TY": 0.23, "OP": 0.22, "WO": 0.22, "SA": 0.22,
    "AY": 0.21, "EX": 0.21, "KE": 0.21, "FR": 0.21, "OO": 0.21,
    "AV": 0.21, "AG": 0.21, "IF": 0.20, "AP": 0.20, "GR": 0.20,
    "OD": 0.19, "BO": 0.19, "SP": 0.19, "FA": 0.19, "UC": 0.19,
    "ND ": 0.0,  # sentinel-safe; ignored
}

_ALPHA_RE = re.compile(r"[^A-Z]")


def clean(text: str) -> str:
    """Upper-case and strip everything but A-Z."""
    return _ALPHA_RE.sub("", text.upper())


# --------------------------------------------------------------------------
# Pre-computed log tables
# --------------------------------------------------------------------------
_FLOOR = 0.01  # percent floor for unseen n-grams

_MONO_LOG = {c: math.log((MONOGRAM_PCT.get(c, _FLOOR)) / 100.0) for c in
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
_BI_LOG = {k: math.log(v / 100.0) for k, v in BIGRAM_PCT.items() if len(k) == 2}
_BI_FLOOR = math.log(_FLOOR / 100.0)


def monogram_score(text: str) -> float:
    """Mean monogram log-probability (higher = more English-like)."""
    t = clean(text)
    if not t:
        return -999.0
    return sum(_MONO_LOG[c] for c in t) / len(t)


def chi_squared(text: str) -> float:
    """Chi-squared distance to English letter distribution (lower = better)."""
    t = clean(text)
    n = len(t)
    if n == 0:
        return float("inf")
    total = 0.0
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        observed = t.count(c)
        expected = MONOGRAM_PCT[c] / 100.0 * n
        if expected > 0:
            total += (observed - expected) ** 2 / expected
    return total


def bigram_score(text: str) -> float:
    """Mean bigram log-probability (higher = more English-like)."""
    t = clean(text)
    if len(t) < 2:
        return -999.0
    total = 0.0
    for i in range(len(t) - 1):
        total += _BI_LOG.get(t[i:i + 2], _BI_FLOOR)
    return total / (len(t) - 1)


# --------------------------------------------------------------------------
# Optional quadgram model (loaded from data file if present)
# --------------------------------------------------------------------------
class QuadgramModel:
    """Log-probability quadgram fitness model loaded from a counts file.

    File format (one entry per line):  ``QUAD COUNT``
    """

    def __init__(self, counts: Dict[str, int]):
        total = sum(counts.values())
        self._log = {}
        for quad, c in counts.items():
            self._log[quad] = math.log10(c / total)
        self._floor = math.log10(0.01 / total)

    @classmethod
    def from_file(cls, path: str) -> "QuadgramModel":
        counts: Dict[str, int] = {}
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 2 and len(parts[0]) == 4:
                    counts[parts[0].upper()] = int(parts[1])
        if not counts:
            raise ValueError(f"no quadgram data parsed from {path}")
        return cls(counts)

    def score(self, text: str) -> float:
        t = clean(text)
        if len(t) < 4:
            return -999.0
        total = 0.0
        for i in range(len(t) - 3):
            total += self._log.get(t[i:i + 4], self._floor)
        return total / (len(t) - 3)


_DEFAULT_QUAD_PATH = os.path.join(os.path.dirname(__file__), "data",
                                  "english_quadgrams.txt")


@lru_cache(maxsize=1)
def _default_quadgram_model() -> Optional[QuadgramModel]:
    if os.path.exists(_DEFAULT_QUAD_PATH):
        try:
            return QuadgramModel.from_file(_DEFAULT_QUAD_PATH)
        except Exception:
            return None
    return None


# --------------------------------------------------------------------------
# Dictionary word coverage
# --------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _common_words() -> frozenset:
    from .data.words import COMMON_WORDS  # local import to avoid cycle
    return COMMON_WORDS


_WORD_SPLIT = re.compile(r"[A-Za-z]+")


def word_coverage(text: str) -> float:
    """Fraction of alphabetic characters that fall inside dictionary words.

    Works on text that still has its spaces.  Returns 0..1.
    """
    words = _WORD_SPLIT.findall(text.upper())
    if not words:
        return 0.0
    hit = 0
    total = 0
    vocab = _common_words()
    for w in words:
        total += len(w)
        if w in vocab:
            hit += len(w)
    return hit / total if total else 0.0


# --------------------------------------------------------------------------
# Unified fitness interface
# --------------------------------------------------------------------------
def fitness(text: str) -> float:
    """Best available englishness score (higher = better).

    Automatically uses the quadgram model when present, else bigrams.
    Scores are internally consistent for ranking within a single run but
    are not comparable across scorers, which is fine for search.
    """
    qm = _default_quadgram_model()
    if qm is not None:
        return qm.score(text)
    return bigram_score(text)


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def confidence(text: str) -> float:
    """A human-facing 0..1 confidence that ``text`` is English plaintext.

    Blends an n-gram plausibility term (vocabulary-independent) with
    dictionary word-coverage, on a scale calibrated so that genuine English
    lands ~0.85-0.95 and random/gibberish text stays below ~0.25.  The score
    is comparable across candidates regardless of which search scorer ran.
    """
    qm = _default_quadgram_model()
    if qm is not None:
        # English ~ -4.5, random ~ -6.2 (mean log10 per quadgram).
        ngram = _clamp01((qm.score(text) + 6.2) / 2.0)
    else:
        # English ~ -6.0, random ~ -8.5 (mean natural-log per bigram).
        ngram = _clamp01((bigram_score(text) + 8.5) / 3.0)
    # Word coverage of ~0.5 already strongly indicates real English.
    cov = _clamp01(word_coverage(text) / 0.5)
    return round(0.5 * ngram + 0.5 * cov, 3)


def describe_scorer() -> str:
    return ("quadgram model" if _default_quadgram_model() is not None
            else "built-in bigram model")
