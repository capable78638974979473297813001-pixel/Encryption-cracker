"""Abbreviation / vowel-drop analysis.

Some "ciphers" are not ciphers at all but **abbreviated English**: the writing
of someone who dropped vowels and strung together initials and shortened words
(a common pattern in notes by people with limited literacy — the leading
hypothesis for the Ricky McCormick notes).  Classical-cipher attacks are the
wrong tool for that; this module is the right one.

It tests the hypothesis honestly, three ways:

1. **Token expansion** — for each letter group, find common English words whose
   *consonant skeleton* (the word with vowels removed) matches, e.g.
   ``WLD -> WORLD / WOULD / WILD``, ``PLSE -> PLEASE / PULSE``.
2. **Consonant word-break** — try to split a long token into a run of common
   vowel-dropped words, testing whether it reads as concatenated English.
3. **Word-initial fit** — compare the note's letter distribution to how English
   *words begin* (relevant if letters are initials), not just overall letters.

It reports evidence; it does not claim a decoding.  Nothing here fabricates a
plaintext — an expansion is labelled a candidate, and a token with no good
match is reported as unexplained.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

_VOWELS = set("AEIOU")
_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "data", "common10k.txt")


def consonant_skeleton(word: str) -> str:
    """Upper-case consonants only (drop vowels and non-letters)."""
    return "".join(c for c in word.upper() if c.isalpha() and c not in _VOWELS)


@lru_cache(maxsize=1)
def _load_words() -> List[str]:
    """Common English words, most-frequent first (frequency = list order)."""
    if not os.path.exists(_WORDLIST_PATH):
        from .data.words import COMMON_WORDS
        return sorted(COMMON_WORDS)
    with open(_WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as fh:
        return [w.strip().upper() for w in fh if w.strip()]


@lru_cache(maxsize=1)
def _skeleton_index() -> Dict[str, List[Tuple[str, int]]]:
    """skeleton -> [(word, freq_rank), ...] ordered by frequency (rank 0 = top)."""
    index: Dict[str, List[Tuple[str, int]]] = {}
    for rank, w in enumerate(_load_words()):
        if not w.isalpha():
            continue
        index.setdefault(consonant_skeleton(w), []).append((w, rank))
    return index


@lru_cache(maxsize=1)
def _word_initial_pct() -> Dict[str, float]:
    """Percent of common English words beginning with each letter."""
    counts = Counter(w[0] for w in _load_words() if w and w[0].isalpha())
    total = sum(counts.values())
    return {c: 100.0 * counts.get(c, 0) / total
            for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}


# --------------------------------------------------------------------------
_TOKEN_RE = re.compile(r"[A-Za-z]+")


def tokenize(text: str) -> List[str]:
    """Split into alphabetic tokens (digits and punctuation are separators)."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.extend(m.group(0).upper() for m in _TOKEN_RE.finditer(line))
    return out


def expand_token(token: str, limit: int = 6) -> List[str]:
    """Common words whose consonant skeleton equals the token's (vowels added)."""
    sk = consonant_skeleton(token)
    if not sk:
        return []
    hits = _skeleton_index().get(sk, [])
    return [w for w, _ in hits[:limit]]


def wordbreak(token: str, max_segments: int = 5) -> Optional[List[str]]:
    """Try to read a token as a run of common vowel-dropped words.

    Returns the best segmentation (list of real words) or None if the token's
    consonant skeleton cannot be covered by common-word skeletons.  Prefers
    fewer segments and more-frequent words, so it does not shatter everything
    into a pile of tiny matches.
    """
    sk = consonant_skeleton(token)
    n = len(sk)
    if n == 0:
        return None
    index = _skeleton_index()
    NEG = float("-inf")
    # best[i] = (score, segmentation) for covering sk[i:]
    best: List[Optional[Tuple[float, List[str]]]] = [None] * (n + 1)
    best[n] = (0.0, [])
    for i in range(n - 1, -1, -1):
        choice: Optional[Tuple[float, List[str]]] = None
        for j in range(i + 1, min(n, i + 8) + 1):   # word skeletons up to len 8
            piece = sk[i:j]
            hits = index.get(piece)
            if not hits:
                continue
            word, rank = hits[0]
            tail = best[j]
            if tail is None:
                continue
            # Score: reward common words, penalise each extra segment and
            # length-1 skeletons (which match far too eagerly).
            freq_score = 1.0 - rank / 10000.0
            seg_penalty = 0.6 + (0.5 if len(piece) == 1 else 0.0)
            score = freq_score - seg_penalty + tail[0]
            if choice is None or score > choice[0]:
                choice = (score, [word] + tail[1])
        best[i] = choice
    result = best[0]
    if result is None or len(result[1]) > max_segments:
        return None
    return result[1]


def _line_tokens(text: str) -> List[List[str]]:
    """Tokenize per line, keeping number groups (digits, '.', '/') as tokens."""
    pat = re.compile(r"[A-Za-z]+|\d[\d./]*")
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        toks = [m.group(0).upper() for m in pat.finditer(line)]
        if toks:
            out.append(toks)
    return out


def choose_word(token: str) -> Tuple[Optional[str], List[str], str]:
    """Pick the single most likely reading of one token.

    Among the candidate words that share the token's consonant skeleton, the
    maximum-likelihood single guess is simply the most frequent word.  Returns
    ``(choice, alternatives, kind)`` where kind is 'strong' (clean single-word
    match on a 3+ skeleton), 'weak' (short/ambiguous), 'segmented' (read as
    several words), or 'none'.  This is a per-token BEST GUESS, not a fact.
    """
    cands = expand_token(token, limit=10)
    sk_len = len(consonant_skeleton(token))
    if cands:
        kind = "strong" if sk_len >= 3 else "weak"
        return cands[0], cands[1:5], kind
    wb = wordbreak(token)
    if wb:
        return " ".join(wb), [], "segmented"
    return None, [], "none"


def best_reading(text: str) -> List[List[Dict]]:
    """Produce one speculative reading of the note, choosing a word per token.

    Returns a list of lines; each line is a list of per-token dicts with the
    original token, the chosen word (or None), alternatives, and kind.  The
    result is explicitly a hypothesis — stringing best-guess words together
    does NOT yield a verified message, and several tokens stay ambiguous.
    """
    reading = []
    for line in _line_tokens(text):
        row = []
        for tok in line:
            if re.match(r"\d", tok):
                row.append({"token": tok, "choice": tok, "alts": [],
                            "kind": "number"})
                continue
            choice, alts, kind = choose_word(tok)
            row.append({"token": tok, "choice": choice, "alts": alts,
                        "kind": kind})
        reading.append(row)
    return reading


def token_context(text: str, token: str) -> Dict:
    """Structural probe for a recurring, un-expandable token (e.g. NCBE).

    Instead of guessing letters, it reports WHERE the token sits: how often it
    ends a line, what precedes and follows it, and its strongest collocations.
    This surfaces structure (a refrain, a delimiter, a list marker) without
    claiming meaning.
    """
    token = token.upper()
    lines = _line_tokens(text)
    total = line_final = 0
    before = Counter()
    after = Counter()
    for line in lines:
        for i, t in enumerate(line):
            if t != token:
                continue
            total += 1
            before[line[i - 1] if i > 0 else "<START>"] += 1
            after[line[i + 1] if i + 1 < len(line) else "<END>"] += 1
            if i == len(line) - 1:
                line_final += 1
    # Acronym reading: treat the letters as initials of separate words.
    initials = [c for c in token if c.isalpha()]
    return {
        "token": token,
        "count": total,
        "line_final": line_final,
        "line_final_fraction": line_final / total if total else 0.0,
        "preceded_by": before.most_common(6),
        "followed_by": after.most_common(6),
        "vowel_insertion": expand_token(token) or None,
        "as_initials": initials,
    }


def analyze(text: str) -> Dict:
    """Run the full abbreviation analysis and return a structured report."""
    tokens = tokenize(text)
    letters = "".join(tokens)

    # Recurring tokens (the note's vocabulary).
    token_freq = Counter(tokens)
    recurring = [(t, c) for t, c in token_freq.most_common() if c >= 2]

    # Per-token expansion / word-break.
    #
    # "strong" = a direct single-word match on a token whose consonant skeleton
    # is at least 3 long.  Short tokens (N, SE, CD ...) match so many words that
    # counting them would wildly overstate how much is really explained, so the
    # honest headline uses the strong count only.
    expansions: List[Dict] = []
    strong = 0
    any_match = 0
    strong_eligible = 0
    for t in sorted(set(tokens), key=lambda x: (-token_freq[x], x)):
        direct = expand_token(t)
        broken = None if direct else wordbreak(t)
        sk_len = len(consonant_skeleton(t))
        is_strong = bool(direct) and sk_len >= 3
        if sk_len >= 3:
            strong_eligible += 1
        if is_strong:
            strong += 1
        if direct or broken:
            any_match += 1
        expansions.append({"token": t, "count": token_freq[t],
                           "direct": direct, "wordbreak": broken,
                           "strong": is_strong})

    # Word-initial fit: compare note letter distribution to how English words
    # begin (chi-squared; lower = better fit).
    wi = _word_initial_pct()
    n = len(letters)
    chi = 0.0
    if n:
        lf = Counter(letters)
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            exp = wi[c] / 100.0 * n
            if exp > 0:
                chi += (lf.get(c, 0) - exp) ** 2 / exp

    return {
        "token_count": len(tokens),
        "unique_tokens": len(set(tokens)),
        "recurring": recurring,
        "expansions": expansions,
        "strong_matches": strong,
        "strong_eligible": strong_eligible,
        "strong_fraction": strong / max(1, strong_eligible),
        "any_match": any_match,
        "word_initial_chi_squared": round(chi, 1),
    }
