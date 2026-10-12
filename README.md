# codebreaker

A serious, dependency-free **classical cryptanalysis toolkit**. It detects and
breaks the ciphers, encodings, and weak hashes that actually *can* be broken —
automatically, from a single command — and it tells you the honest truth about
the ones that can't.

```bash
python -m codebreaker auto "Wklv lv d vhfuhw phvvdjh"
```

```
[1] caesar   confidence=0.85 [#################   ]
    key: 3
    This is a secret message
```

---

## What it does

| Command | What it breaks | How |
|---|---|---|
| `auto` | *Anything classical* — tries everything and ranks the results | Full attack battery + English scoring |
| `caesar` | Caesar / ROT-N | Brute-force all 26 shifts, χ² ranking |
| `affine` | Affine `(ax+b) mod 26` | Brute-force all 312 valid keys |
| `vigenere` | Vigenère | IoC + Kasiski key-length estimation, per-column solving |
| `substitution` | Monoalphabetic substitution | Hill-climbing with quadgram + dictionary fitness |
| `xor` | Single-byte & repeating-key XOR | Hamming-distance key-size detection |
| `transposition` | Rail fence & columnar | Exhaustive search over keys |
| `atbash` / `morse` | Atbash, Morse code | Direct transforms |
| `decode` | Layered base64 / base32 / hex / binary / URL | Recursive peeling |
| `analyze` | *Tells you what you're looking at* | IoC, entropy, frequency, Kasiski |
| `hash` | Weak **unsalted** hashes (MD5, SHA-1/2/3, …) | Dictionary + rules, bounded brute force |

Every result comes with a **confidence score** (how English-like the output is)
so you can tell a real break from a near-miss at a glance.

## Quick start

```bash
# No install needed — pure standard library.
python -m codebreaker auto "Gur dhvpx oebja sbk whzcf bire gur ynml qbt"

# Or install the `codebreaker` command:
pip install -e .
codebreaker auto --in message.txt
```

Input comes from an argument, `--in FILE`, or stdin (so you can pipe stages
together). Examples:

```bash
# Figure out an unknown string
echo "SGVsbG8gd29ybGQ=" | python3 -m codebreaker decode

# Break a Vigenère cipher with an unknown key
python3 -m codebreaker vigenere --in ciphertext.txt

# Analyze before attacking
python3 -m codebreaker analyze --in mystery.txt

# Audit a leaked MD5 against a wordlist (authorised use only)
python3 -m codebreaker hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
```

## Make it even stronger

The substitution solver and auto-ranker use an English **quadgram** model. A
compact one ships in `codebreaker/data/`. Point it at a larger corpus to make
it sharper:

```bash
python3 -m codebreaker build-model my_big_english_corpus.txt
```

Bigger corpus → better statistics → cleaner breaks on short or tricky
ciphertext.

## The honest truth about "cracking any encryption"

This tool is genuinely strong at what it targets, and it will beat a human with
a pencil every time. But any program — this one, a nation-state's, anyone's —
runs into the same wall, and it's worth understanding *why*, because it's the
most important thing in cryptography:

- **Classical ciphers (Caesar, Vigenère, substitution, transposition, XOR):**
  broken here, routinely, often instantly. Their weakness is that the structure
  of language survives encryption, and statistics expose it.

- **Modern symmetric encryption (AES-256) and public-key crypto (RSA-2048,
  elliptic curve):** *cannot* be broken by brute force. This is not a matter of
  being clever enough or having a faster computer. A 256-bit key has about
  10⁷⁷ possibilities — roughly the number of atoms in the observable universe.
  Every computer ever built, running together until the sun burns out, would
  not test a meaningful fraction of them. The math is sound and public; there
  is no secret trick, and a tool that claims to brute-force AES is lying.

- **So how is strong crypto ever defeated in the real world?** Almost never by
  attacking the algorithm. It's defeated by attacking the *things around* it:
  weak or reused passwords, keys stored carelessly, buggy implementations,
  default credentials, and people who can be tricked. That's where real
  codebreaking happens — and it's why this toolkit includes hash auditing and
  honest hash identification: finding the weak link is the actual job.

If you hand `codebreaker` something it can't break, it will say so and tell you
what it *is* (via `analyze`), rather than spinning forever or faking a result.
That honesty is a feature.

## Scope & responsible use

Built for **learning, CTF challenges, and authorised security work** (e.g.
auditing the strength of your own password hashes). The hash-cracking features
are deliberately limited to weak, unsalted digests and bounded brute force;
properly salted/stretched hashes (bcrypt, scrypt, argon2) are identified and
left alone. Only test systems and data you own or are authorised to assess.

## Project layout

```
codebreaker/
  cli.py            command-line interface
  detect.py         auto-detection + "try everything" orchestrator
  analysis.py       IoC, entropy, Kasiski, frequency
  scoring.py        English-fitness models (monogram/bigram/quadgram/words)
  encodings.py      base64/32/hex/binary/url + recursive decoder
  hashes.py         hash identification + dictionary/brute-force
  classical/        one module per cipher family
  data/             corpus + generated quadgram model + word list
tests/              round-trip + end-to-end solve tests
```

## Tests

```bash
python3 tests/test_ciphers.py        # no dependencies
# or, if you have pytest:
pytest tests/
```

## License

MIT.
