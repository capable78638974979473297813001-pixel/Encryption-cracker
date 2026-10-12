"""Auto-detection and the one-call "crack anything classical" orchestrator.

``auto_crack`` runs the full battery of attacks appropriate to the input and
returns the strongest candidates ranked by English-fitness/confidence.  It is
the engine behind ``codebreaker auto``.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from . import encodings
from .analysis import (ENGLISH_IOC, RANDOM_IOC, index_of_coincidence,
                       printable_ratio, shannon_entropy)
from .classical import (affine, atbash, caesar, morse, substitution,
                        transposition, vigenere, xor)
from .core import Candidate
from .scoring import clean, confidence

# Confidence thresholds for the honest verdict (see ``assess``).
SOLVED_THRESHOLD = 0.55       # clearly English plaintext recovered
# Set deliberately above the confidence that random noise can reach by chance
# (~0.44 measured), so pure gibberish is never dignified as a "lead".
PARTIAL_THRESHOLD = 0.48


def profile(text: str) -> dict:
    """Quick structural read on an input to guide the attack order."""
    raw = text.strip()
    letters = clean(text)
    data = raw.encode("utf-8", "replace")
    return {
        "length": len(raw),
        "letters": len(letters),
        "ioc": round(index_of_coincidence(text), 4),
        "entropy_bits_per_byte": round(shannon_entropy(data), 3),
        "printable_ratio": round(printable_ratio(data), 3),
        "looks_like_morse": morse.looks_like_morse(raw),
        "alpha_only": letters == "".join(ch for ch in raw if ch.isalpha()),
    }


def auto_crack(text: str, deep: bool = True, top: int = 5) -> List[Candidate]:
    """Run every applicable classical attack and return ranked candidates."""
    raw = text.strip()
    results: List[Candidate] = []

    # 0. Layered encodings (base64/hex/binary/...).
    decoded, steps = encodings.recursive_decode(raw)
    if steps and decoded != raw:
        results.append(Candidate(
            score=50.0 + confidence(decoded),  # strongly prefer clean decodes
            cipher="encoding:" + ">".join(steps),
            plaintext=decoded, key=">".join(steps),
            confidence=confidence(decoded),
            meta={"layers": steps}))

    # 1. Morse.
    if morse.looks_like_morse(raw):
        dec = morse.decode(raw)
        if dec:
            results.append(Candidate(
                score=40.0 + confidence(dec), cipher="morse", plaintext=dec,
                key="morse", confidence=confidence(dec)))

    letters = clean(text)

    # 2. Alphabetic classical ciphers (need letters to work on).
    if len(letters) >= 1:
        results += caesar.solve(text, top=2)
        results += atbash.solve(text)
        results += affine.solve(text, top=2)

    if len(letters) >= 20:
        results += vigenere.solve(text, top=2)
        results += transposition.solve_railfence(text, top=2)
        if len(letters) <= 400:
            results += transposition.solve_columnar(text, top=2)

    if deep and len(letters) >= 60:
        results += substitution.solve(text, restarts=20, iterations=2000, top=2)

    # 3. XOR on raw bytes (useful for hex/base64-wrapped binary too).
    try:
        data = raw.encode("utf-8")
        results += xor.solve_single_byte(data, top=1)
        if len(data) >= 8:
            results += xor.solve_repeating_key(data, top=1)
    except Exception:
        pass

    # Re-score every candidate on ONE honest English scale so results from
    # different solvers (whose internal scores are not comparable) can be
    # ranked fairly.  This stops, e.g., a gibberish XOR guess from
    # out-ranking a correct classical decryption.
    for c in results:
        c.confidence = confidence(c.plaintext)

    results.sort(key=lambda c: c.confidence, reverse=True)

    # Deduplicate near-identical plaintexts.
    out, seen = [], set()
    for c in results:
        sig = c.plaintext.strip()[:120].lower()
        if sig in seen:
            continue
        seen.add(sig)
        out.append(c)
        if len(out) >= top:
            break
    return out


def assess(text: str, candidates: Optional[List[Candidate]] = None) -> Dict:
    """Produce an HONEST verdict about whether the input was solved.

    This is the feature that keeps the tool from ever implying a break it did
    not achieve.  It classifies the best candidate's confidence and, when no
    confident solution exists, explains what the input *looks* like instead of
    pretending.  It never fabricates a plaintext.

    Returns a dict with ``verdict`` (one of "solved", "partial", "unsolved"),
    a human-readable ``summary``, and a list of diagnostic ``notes``.
    """
    if candidates is None:
        candidates = auto_crack(text, top=5)
    prof = profile(text)
    best = candidates[0].confidence if candidates else 0.0

    notes: List[str] = []
    raw = text.strip()
    digits = sum(ch.isdigit() for ch in raw)
    letters = prof["letters"]
    has_parens = bool(re.search(r"[()]", raw))

    # Structural observations (facts about the input, not guesses).
    if digits and letters:
        frac = digits / max(1, digits + letters)
        notes.append(
            f"contains {digits} digits mixed with letters "
            f"({frac:.0%} digits) — not a pure alphabetic classical cipher; "
            f"consistent with a code/nomenclator, shorthand, or abbreviations")
    if has_parens:
        notes.append("uses parentheses — often structural markers rather than "
                     "encrypted letters")
    if prof["printable_ratio"] < 0.9:
        notes.append(f"entropy {prof['entropy_bits_per_byte']} bits/byte with "
                     f"non-printable bytes — looks like binary/encrypted data, "
                     f"not a classical cipher")
    elif letters >= 20:
        ioc = prof["ioc"]
        if abs(ioc - ENGLISH_IOC) < 0.008:
            notes.append(f"index of coincidence {ioc} is English-like — "
                         f"stats fit a monoalphabetic cipher or a transposition")
        elif abs(ioc - RANDOM_IOC) < 0.008:
            notes.append(f"index of coincidence {ioc} is near-random — fits a "
                         f"polyalphabetic cipher or non-English/meaningless text")
        else:
            notes.append(f"index of coincidence {ioc} is unusual — does not "
                         f"cleanly match English or random text")
    if letters and letters < 20 and not digits:
        notes.append("very short — too little text for statistical attacks to "
                     "be reliable")

    if best >= SOLVED_THRESHOLD:
        verdict = "solved"
        summary = (f"Solved with {best:.0%} confidence as "
                   f"{candidates[0].cipher}.")
    elif best >= PARTIAL_THRESHOLD:
        verdict = "partial"
        summary = (f"Partial/uncertain: best candidate is only {best:.0%} "
                   f"confident ({candidates[0].cipher}). Treat it as a lead, "
                   f"not an answer — it may be wrong.")
    else:
        verdict = "unsolved"
        summary = (f"NOT SOLVED. No decryption resembling English was found "
                   f"(best confidence {best:.0%}). This does not match any "
                   f"cipher this tool supports. Candidates below are "
                   f"low-confidence and are most likely wrong.")
    return {"verdict": verdict, "summary": summary, "confidence": best,
            "notes": notes, "profile": prof}
