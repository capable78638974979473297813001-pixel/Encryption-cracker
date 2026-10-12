"""Auto-detection and the one-call "crack anything classical" orchestrator.

``auto_crack`` runs the full battery of attacks appropriate to the input and
returns the strongest candidates ranked by English-fitness/confidence.  It is
the engine behind ``codebreaker auto``.
"""

from __future__ import annotations

from typing import List

from . import encodings
from .analysis import (index_of_coincidence, printable_ratio, shannon_entropy)
from .classical import (affine, atbash, caesar, morse, substitution,
                        transposition, vigenere, xor)
from .core import Candidate
from .scoring import clean, confidence


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
