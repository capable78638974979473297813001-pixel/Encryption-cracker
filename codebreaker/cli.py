"""Command-line interface for the codebreaker toolkit.

Run ``python -m codebreaker --help`` for the full command list.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import abbrev, analysis, encodings, hashes
from .classical import (affine, atbash, caesar, morse, substitution,
                        transposition, vigenere, xor)
from .core import Candidate
from .detect import assess, auto_crack, profile
from .scoring import describe_scorer


def _read_input(args) -> str:
    if getattr(args, "text", None):
        return args.text
    if getattr(args, "infile", None):
        with open(args.infile, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    data = sys.stdin.read()
    if not data:
        raise SystemExit("error: no input (pass TEXT, --in FILE, or pipe stdin)")
    return data


def _print_candidates(cands: List[Candidate], verbose: bool = False) -> None:
    if not cands:
        print("  (no candidates found)")
        return
    for i, c in enumerate(cands, 1):
        bar = "#" * int(c.confidence * 20)
        print(f"\n[{i}] {c.cipher}   confidence={c.confidence:0.2f} "
              f"[{bar:<20}]")
        if c.key is not None:
            print(f"    key: {c.key_str()}")
        if verbose and c.meta:
            print(f"    meta: {c.meta}")
        preview = c.plaintext if len(c.plaintext) <= 240 or verbose \
            else c.plaintext[:240] + " ..."
        print(f"    {preview}")


# --------------------------------------------------------------------------
# sub-command handlers
# --------------------------------------------------------------------------
def cmd_auto(args):
    text = _read_input(args)
    print(f"scorer: {describe_scorer()}")
    cands = auto_crack(text, deep=not args.fast, top=args.top)
    verdict = assess(text, cands)

    print(f"\n=== verdict: {verdict['verdict'].upper()} ===")
    print(verdict["summary"])
    if verdict["verdict"] != "solved" and verdict["notes"]:
        print("\ndiagnostics:")
        for n in verdict["notes"]:
            print(f"  - {n}")

    print("\n=== best candidates ===")
    _print_candidates(cands, args.verbose)


def cmd_analyze(args):
    text = _read_input(args)
    data = text.encode("utf-8", "replace")
    print(f"length (chars)      : {len(text.strip())}")
    print(f"index of coincidence: {analysis.index_of_coincidence(text):0.4f} "
          f"(English~0.0667, random~0.0385)")
    print(f"entropy (bits/byte) : {analysis.shannon_entropy(data):0.3f} "
          f"(random/encrypted ~8.0)")
    print(f"printable ratio     : {analysis.printable_ratio(data):0.3f}")
    print("\nlikely polyalphabetic key lengths (IoC):")
    for k, v in analysis.estimate_key_length_ioc(text)[:6]:
        print(f"    len {k:>2}: avg IoC {v:0.4f}")
    print("\nKasiski key-length votes:")
    for k, v in analysis.kasiski_examination(text)[:6]:
        print(f"    len {k:>2}: {v} votes")
    print("\ntop letter frequencies:")
    freq = analysis.frequency(text)
    for c, f in sorted(freq.items(), key=lambda kv: kv[1], reverse=True)[:8]:
        print(f"    {c}: {f*100:0.1f}%")


def cmd_caesar(args):
    text = _read_input(args)
    if args.shift is not None:
        print(caesar.decrypt(text, args.shift) if not args.encrypt
              else caesar.encrypt(text, args.shift))
    else:
        _print_candidates(caesar.solve(text, top=args.top), args.verbose)


def cmd_vigenere(args):
    text = _read_input(args)
    if args.key:
        print(vigenere.encrypt(text, args.key) if args.encrypt
              else vigenere.decrypt(text, args.key))
    else:
        _print_candidates(vigenere.solve(text, top=args.top,
                                         key_len=args.keylen), args.verbose)


def cmd_substitution(args):
    text = _read_input(args)
    _print_candidates(substitution.solve(
        text, restarts=args.restarts, iterations=args.iterations,
        top=args.top, seed=args.seed), args.verbose)


def cmd_affine(args):
    text = _read_input(args)
    if args.a is not None and args.b is not None:
        print(affine.encrypt(text, args.a, args.b) if args.encrypt
              else affine.decrypt(text, args.a, args.b))
    else:
        _print_candidates(affine.solve(text, top=args.top), args.verbose)


def cmd_xor(args):
    text = _read_input(args)
    data = bytes.fromhex(text.strip()) if args.hex else text.encode("utf-8")
    if args.key:
        key = bytes.fromhex(args.key) if args.key_hex else args.key.encode()
        out = xor.xor_bytes(data, key)
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.write(b"\n")
    elif args.single:
        _print_candidates(xor.solve_single_byte(data, top=args.top),
                          args.verbose)
    else:
        _print_candidates(xor.solve_repeating_key(data, top=args.top),
                          args.verbose)


def cmd_transposition(args):
    text = _read_input(args)
    cands = []
    cands += transposition.solve_railfence(text, top=args.top)
    cands += transposition.solve_columnar(text, max_cols=args.max_cols,
                                           top=args.top)
    cands.sort(reverse=True)
    _print_candidates(cands[:args.top], args.verbose)


def cmd_atbash(args):
    text = _read_input(args)
    print(atbash.decrypt(text))


def cmd_morse(args):
    text = _read_input(args)
    print(morse.encode(text) if args.encode else morse.decode(text))


def cmd_decode(args):
    text = _read_input(args)
    decoded, steps = encodings.recursive_decode(text)
    if steps:
        print(f"layers: {' > '.join(steps)}\n")
        print(decoded)
    else:
        print("(no reversible encoding detected)")


def cmd_hash(args):
    info = hashes.identify(args.digest)
    print(f"input       : {info['input']}")
    print(f"candidates  : {', '.join(info['candidates']) or '(unknown)'}")
    print(f"attackable  : {info['attackable']}")
    if info.get("reason"):
        print(f"note        : {info['reason']}")
    if not info["attackable"]:
        return
    result = None
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            result = hashes.crack_dictionary(args.digest, fh, algo=args.algo)
    if not result and args.brute:
        print(f"\nbrute forcing up to length {args.max_len} ...")
        result = hashes.crack_bruteforce(args.digest, max_len=args.max_len,
                                         algo=args.algo)
    if result:
        print(f"\n*** CRACKED ***  {result}")
    else:
        print("\nnot found with the given attack.")


def _kind_mark(kind):
    return {"strong": " ", "weak": "?", "segmented": "~", "none": "!",
            "number": "#"}.get(kind, " ")


def cmd_abbrev(args):
    text = _read_input(args)

    if args.context:
        ctx = abbrev.token_context(text, args.context)
        print(f"structural probe: {ctx['token']}  (x{ctx['count']})")
        print(f"ends a line: {ctx['line_final']}/{ctx['count']} "
              f"({ctx['line_final_fraction']:.0%})")
        print(f"preceded by: {ctx['preceded_by']}")
        print(f"followed by: {ctx['followed_by']}")
        print(f"vowel-insertion reading: {ctx['vowel_insertion'] or 'none'}")
        print(f"as initials: {'.'.join(ctx['as_initials'])}.")
        print("\nThis describes WHERE the token sits, not what it means. "
              "No meaning is claimed.")
        return

    if args.read:
        print("SPECULATIVE reconstruction — one chosen word per token.")
        print("Marks:  ? ambiguous (alternatives exist)   ~ segmented guess   "
              "! no match   # number\n")
        for row in abbrev.best_reading(text):
            parts = []
            for c in row:
                word = c["choice"] if c["choice"] else c["token"]
                parts.append(f"{word}{_kind_mark(c['kind'])}".strip())
            print("  " + " ".join(parts))
        print("\nThis is a hypothesis, not a decoding. Many tokens are "
              "ambiguous and the transcription itself is disputed; do not "
              "read this as the message.")
        return

    rep = abbrev.analyze(text)
    print(f"tokens: {rep['token_count']}  unique: {rep['unique_tokens']}")
    print(f"strong matches (len>=3 token -> one common word): "
          f"{rep['strong_matches']}/{rep['strong_eligible']} "
          f"({rep['strong_fraction']:.0%})")
    print("  (short tokens are excluded — they match too many words to count)")
    print(f"word-initial chi-squared: {rep['word_initial_chi_squared']} "
          f"(lower = closer to how English words begin)")

    if rep["recurring"]:
        print("\nrecurring tokens (the note's own vocabulary):")
        for t, c in rep["recurring"][:15]:
            print(f"  {t:<14} x{c}")

    print("\nper-token candidate expansions (vowel-drop hypothesis):")
    print("  * these are HYPOTHESES, not a decoding; '-' means no good match\n")
    for e in rep["expansions"]:
        if args.only_matched and not (e["direct"] or e["wordbreak"]):
            continue
        tag = f"{e['token']} (x{e['count']})" if e["count"] > 1 else e["token"]
        if e["direct"]:
            val = "  /  ".join(e["direct"])
        elif e["wordbreak"]:
            val = " + ".join(e["wordbreak"]) + "   [segmented]"
        else:
            val = "-"
        print(f"  {tag:<18} -> {val}")

    # Honest closing verdict.
    top = rep["recurring"][0] if rep["recurring"] else None
    top_strong = False
    if top:
        for e in rep["expansions"]:
            if e["token"] == top[0]:
                top_strong = e["strong"]
                break
    print("\n=== verdict ===")
    print(f"{rep['strong_fraction']:.0%} of multi-letter tokens map cleanly to "
          f"a single common English word — consistent with abbreviated / "
          f"vowel-dropped English, NOT a math cipher.")
    if top and not top_strong:
        print(f"But the most frequent unit, {top[0]} (x{top[1]}), has no clean "
              f"English reading, and many tokens have several candidates.")
    print("This is EVIDENCE about how the note was written. It is NOT a "
          "decoding: no full, verifiable plaintext is produced, and none "
          "should be claimed.")


def cmd_build_model(args):
    """Build an English quadgram model from a corpus for maximum accuracy."""
    from collections import Counter
    import os
    from .scoring import clean, _DEFAULT_QUAD_PATH
    with open(args.corpus, "r", encoding="utf-8", errors="ignore") as fh:
        text = clean(fh.read())
    counts = Counter(text[i:i + 4] for i in range(len(text) - 3))
    out_path = args.out or _DEFAULT_QUAD_PATH
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for quad, c in counts.most_common():
            fh.write(f"{quad} {c}\n")
    print(f"wrote {len(counts)} quadgrams to {out_path}")
    print("the engine will now use quadgram fitness automatically.")


# --------------------------------------------------------------------------
# argument parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codebreaker",
        description="Classical cryptanalysis toolkit: detect and break "
                    "classical ciphers, encodings, and weak hashes.")
    p.add_argument("--version", action="store_true", help="print version")
    sub = p.add_subparsers(dest="command")

    def add_common(sp):
        sp.add_argument("text", nargs="?", help="input text (or use --in/stdin)")
        sp.add_argument("--in", dest="infile", help="read input from file")
        sp.add_argument("--top", type=int, default=5, help="candidates to show")
        sp.add_argument("-v", "--verbose", action="store_true")

    sp = sub.add_parser("auto", help="auto-detect and crack (try everything)")
    add_common(sp)
    sp.add_argument("--fast", action="store_true",
                    help="skip the slower substitution search")
    sp.set_defaults(func=cmd_auto)

    sp = sub.add_parser("analyze", help="statistical analysis only")
    add_common(sp)
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("caesar", help="Caesar / ROT-N")
    add_common(sp)
    sp.add_argument("--shift", type=int, help="apply a specific shift")
    sp.add_argument("--encrypt", action="store_true")
    sp.set_defaults(func=cmd_caesar)

    sp = sub.add_parser("vigenere", help="Vigenere")
    add_common(sp)
    sp.add_argument("--key", help="use a known key")
    sp.add_argument("--keylen", type=int, help="force a key length when solving")
    sp.add_argument("--encrypt", action="store_true")
    sp.set_defaults(func=cmd_vigenere)

    sp = sub.add_parser("substitution", help="monoalphabetic substitution")
    add_common(sp)
    sp.add_argument("--restarts", type=int, default=25)
    sp.add_argument("--iterations", type=int, default=2500)
    sp.add_argument("--seed", type=int, help="RNG seed (reproducible)")
    sp.set_defaults(func=cmd_substitution)

    sp = sub.add_parser("affine", help="affine cipher")
    add_common(sp)
    sp.add_argument("--a", type=int)
    sp.add_argument("--b", type=int)
    sp.add_argument("--encrypt", action="store_true")
    sp.set_defaults(func=cmd_affine)

    sp = sub.add_parser("xor", help="XOR (single-byte / repeating-key)")
    add_common(sp)
    sp.add_argument("--hex", action="store_true", help="input is hex bytes")
    sp.add_argument("--single", action="store_true", help="force single-byte")
    sp.add_argument("--key", help="apply a known key")
    sp.add_argument("--key-hex", action="store_true", help="--key is hex")
    sp.set_defaults(func=cmd_xor)

    sp = sub.add_parser("transposition", help="rail fence / columnar")
    add_common(sp)
    sp.add_argument("--max-cols", type=int, default=7)
    sp.set_defaults(func=cmd_transposition)

    sp = sub.add_parser("atbash", help="Atbash")
    add_common(sp)
    sp.set_defaults(func=cmd_atbash)

    sp = sub.add_parser("morse", help="Morse code")
    add_common(sp)
    sp.add_argument("--encode", action="store_true", help="text -> morse")
    sp.set_defaults(func=cmd_morse)

    sp = sub.add_parser("decode", help="recursively peel encodings")
    add_common(sp)
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("hash", help="identify and crack weak hashes")
    sp.add_argument("digest", help="the hash to identify/crack")
    sp.add_argument("--wordlist", help="dictionary attack with this file")
    sp.add_argument("--brute", action="store_true", help="bounded brute force")
    sp.add_argument("--max-len", type=int, default=5)
    sp.add_argument("--algo", help="force algorithm (md5/sha1/sha256/...)")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.set_defaults(func=cmd_hash)

    sp = sub.add_parser("abbrev",
                        help="abbreviation / vowel-drop analysis (abbreviated "
                             "English, not a cipher)")
    add_common(sp)
    sp.add_argument("--only-matched", action="store_true",
                    help="show only tokens that expand to common English")
    sp.add_argument("--read", action="store_true",
                    help="print a speculative best-guess reconstruction")
    sp.add_argument("--context", metavar="TOKEN",
                    help="structural probe of one recurring token (e.g. NCBE)")
    sp.set_defaults(func=cmd_abbrev)

    sp = sub.add_parser("build-model",
                        help="build quadgram model from a text corpus")
    sp.add_argument("corpus", help="path to a large English text file")
    sp.add_argument("--out", help="output path (default: bundled data dir)")
    sp.set_defaults(func=cmd_build_model)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        from . import __version__
        print(f"codebreaker {__version__}")
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
