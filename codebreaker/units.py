"""Internal-structure mining: the note's own "building blocks".

When a text is a concatenated abbreviation system (as the McCormick notes
appear to be), the meaningful units live *inside* the tokens.  This module
recovers that inventory directly from the data:

* repeated substrings (candidate morphemes), with how many DISTINCT tokens
  each appears in (spread matters more than raw count);
* the dominant prefixes and suffixes, which expose the writer's habits
  (e.g. a terminal -E / -SE appended to most tokens).

Everything here is measured, not guessed.  It characterises *how* the note
was written; it does not claim what it says.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

_TOKEN_RE = re.compile(r"[A-Za-z]+")


def _tokens(text: str) -> List[str]:
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.extend(m.group(0).upper() for m in _TOKEN_RE.finditer(line))
    return out


def repeated_substrings(text: str, min_len: int = 2, max_len: int = 5,
                        min_count: int = 3) -> List[Tuple[str, int, int]]:
    """Return ``(substring, count, token_spread)`` for recurring substrings.

    ``token_spread`` is the number of distinct tokens the substring appears in,
    which distinguishes a real shared unit from a quirk of one repeated token.
    Sorted by spread then count, descending.
    """
    toks = _tokens(text)
    count: Counter = Counter()
    spread: Dict[str, set] = defaultdict(set)
    for ti, t in enumerate(toks):
        for L in range(min_len, max_len + 1):
            for i in range(len(t) - L + 1):
                s = t[i:i + L]
                count[s] += 1
                spread[s].add(ti)
    rows = [(s, c, len(spread[s])) for s, c in count.items() if c >= min_count]
    rows.sort(key=lambda r: (r[2], r[1]), reverse=True)
    return rows


def affixes(text: str) -> Dict:
    """Prefix/suffix habits of the token set."""
    toks = _tokens(text)
    n = len(toks)
    suf2 = Counter(t[-2:] for t in toks if len(t) >= 2)
    pre2 = Counter(t[:2] for t in toks if len(t) >= 2)
    end_e = sum(1 for t in toks if t.endswith("E"))
    end_se = sum(1 for t in toks if t.endswith("SE"))
    return {
        "tokens": n,
        "end_E": end_e,
        "end_E_fraction": end_e / n if n else 0.0,
        "end_SE": end_se,
        "end_SE_fraction": end_se / n if n else 0.0,
        "top_suffixes": suf2.most_common(8),
        "top_prefixes": pre2.most_common(8),
    }


def stems(text: str, suffix: str = "SE") -> List[str]:
    """Tokens with ``suffix`` removed (to inspect the underlying skeletons)."""
    toks = _tokens(text)
    return [t[:-len(suffix)] for t in toks
            if t.endswith(suffix) and len(t) > len(suffix)]


def cross_validate(text: str) -> Dict:
    """Split the note into halves and check that key habits hold in BOTH.

    Splits on page markers (``# --- Page N ---``) if present, else at the
    midpoint.  A habit that appears independently in two separately-written
    halves is a real property of the writer, not an artifact of one block or
    one transcription.
    """
    marker = re.compile(r"#.*page\s*\d", re.I)
    if any(marker.search(l) for l in text.splitlines()):
        chunks, cur = [], []
        for line in text.splitlines():
            if marker.search(line):
                if any(c.strip() and not c.lstrip().startswith("#") for c in cur):
                    chunks.append("\n".join(cur))
                cur = []
            else:
                cur.append(line)
        if any(c.strip() and not c.lstrip().startswith("#") for c in cur):
            chunks.append("\n".join(cur))
        halves = chunks[-2:] if len(chunks) >= 2 else chunks
    else:
        toks = _tokens(text)
        mid = len(toks) // 2
        halves = [" ".join(toks[:mid]), " ".join(toks[mid:])]

    out = []
    for h in halves:
        aff = affixes(h)
        ht = _tokens(h)
        out.append({
            "tokens": aff["tokens"],
            "end_E_fraction": aff["end_E_fraction"],
            "end_SE_fraction": aff["end_SE_fraction"],
            "NCBE": sum(1 for t in ht if t == "NCBE"),
            "has_CB": sum(1 for t in ht if "CB" in t),
            "has_WLD": sum(1 for t in ht if "WLD" in t),
        })
    return {"halves": out}


def analyze(text: str) -> Dict:
    subs = repeated_substrings(text)
    aff = affixes(text)
    # "cores": recurring units that are not merely the dominant affixes.
    core = [r for r in subs if r[0] not in ("SE", "RSE", "NSE", "LSE", "TSE",
                                            "BE", "RS") and r[2] >= 5]
    return {"substrings": subs, "affixes": aff, "cores": core[:12]}
