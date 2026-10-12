"""Hash identification and recovery for weak/unsalted digests.

Intended for authorised password-strength auditing and CTF challenges.
Dictionary and bounded brute-force attacks only work against *weak* hashes
(unsalted MD5/SHA-family, etc.).  Properly salted, stretched hashes
(bcrypt/scrypt/argon2) are not recoverable here by design, and the tool
says so rather than pretending otherwise.
"""

from __future__ import annotations

import hashlib
import itertools
import re
import string
from typing import Dict, Iterable, List, Optional

# Map digest hex-length -> plausible algorithms.
_BY_LENGTH: Dict[int, List[str]] = {
    32: ["md5", "md4"],
    40: ["sha1", "ripemd160"],
    56: ["sha224", "sha3_224"],
    64: ["sha256", "sha3_256", "blake2s"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512", "blake2b"],
}

# Algorithms we can attack with raw hashlib.
_RAW_ALGOS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512",
              "sha3_224", "sha3_256", "sha3_384", "sha3_512",
              "blake2b", "blake2s"}

# Prefixes that indicate a slow, salted hash we cannot/should not brute force.
_STRONG_PREFIXES = {
    "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt",
    "$argon2": "argon2", "$scrypt$": "scrypt",
    "$6$": "sha512crypt", "$5$": "sha256crypt", "$1$": "md5crypt",
    "$y$": "yescrypt",
}


def identify(digest: str) -> Dict[str, object]:
    """Identify a hash's likely type and whether it is attackable here."""
    d = digest.strip()
    for prefix, name in _STRONG_PREFIXES.items():
        if d.startswith(prefix):
            return {"input": d, "candidates": [name], "attackable": False,
                    "reason": f"{name} is salted & stretched; use a proper "
                              f"cracker (hashcat/john) with authorisation."}
    if re.fullmatch(r"[0-9a-fA-F]+", d):
        cands = _BY_LENGTH.get(len(d), [])
        attackable = any(c in _RAW_ALGOS for c in cands)
        return {"input": d, "candidates": cands, "attackable": attackable,
                "reason": "" if cands else "unknown length; not a common raw hash"}
    return {"input": d, "candidates": [], "attackable": False,
            "reason": "not a hex digest"}


def _digest(algo: str, data: bytes) -> str:
    return hashlib.new(algo, data).hexdigest()


def _candidate_algos(digest: str, algo: Optional[str]) -> List[str]:
    if algo:
        return [algo]
    return [a for a in _BY_LENGTH.get(len(digest.strip()), []) if a in _RAW_ALGOS]


def crack_dictionary(digest: str, words: Iterable[str],
                     algo: Optional[str] = None,
                     rules: bool = True) -> Optional[Dict[str, str]]:
    """Try each word (optionally with simple mangling rules) against the hash."""
    target = digest.strip().lower()
    algos = _candidate_algos(target, algo)
    if not algos:
        return None
    for word in words:
        word = word.rstrip("\n")
        for cand in (_mangle(word) if rules else [word]):
            data = cand.encode("utf-8", "replace")
            for a in algos:
                if _digest(a, data) == target:
                    return {"plaintext": cand, "algorithm": a}
    return None


_SUFFIXES = ["", "1", "12", "123", "1234", "!", "?", ".", "01", "007",
             "2023", "2024", "2025", "69", "420"]


def _mangle(word: str) -> Iterable[str]:
    """A compact best-practice rule set (like a stripped-down JtR ruleset).

    Composes case transforms with common appended suffixes and a leetspeak
    pass — the mutations that account for most human-chosen passwords.
    """
    seen = set()
    bases = [word, word.lower(), word.upper(), word.capitalize(),
             word[::-1],
             word.translate(str.maketrans("aAeEiIoOsS", "4433110055"))]
    for base in bases:
        for suffix in _SUFFIXES:
            v = base + suffix
            if v not in seen:
                seen.add(v)
                yield v


def crack_bruteforce(digest: str, max_len: int = 5,
                     charset: str = string.ascii_lowercase + string.digits,
                     algo: Optional[str] = None,
                     limit: int = 50_000_000) -> Optional[Dict[str, str]]:
    """Bounded brute force.  Grows exponentially — keep ``max_len`` small.

    ``limit`` caps the number of attempts so the call always terminates.
    """
    target = digest.strip().lower()
    algos = _candidate_algos(target, algo)
    if not algos:
        return None
    tried = 0
    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            tried += 1
            if tried > limit:
                return None
            cand = "".join(combo)
            data = cand.encode()
            for a in algos:
                if _digest(a, data) == target:
                    return {"plaintext": cand, "algorithm": a,
                            "attempts": tried}
    return None
