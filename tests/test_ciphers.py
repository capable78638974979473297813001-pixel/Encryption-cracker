"""Round-trip and end-to-end solve tests for the codebreaker toolkit."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from codebreaker import (abbrev, addresses, encodings,  # noqa: E402
                        phonetic, rebus, units)
from codebreaker.classical import (affine, atbash, caesar, morse,  # noqa: E402
                                   substitution, transposition, vigenere, xor)
from codebreaker.detect import assess, auto_crack  # noqa: E402
from codebreaker.hashes import crack_dictionary, identify  # noqa: E402

PLAIN = ("the quick brown fox jumps over the lazy dog and then the dog "
         "decided to chase the fox across the wide green meadow near the "
         "river while the sun began to set behind the distant hills")


# --------------------------- round trips ---------------------------------
def test_caesar_roundtrip():
    assert caesar.decrypt(caesar.encrypt(PLAIN, 7), 7) == PLAIN


def test_affine_roundtrip():
    assert affine.decrypt(affine.encrypt(PLAIN, 5, 8), 5, 8) == PLAIN


def test_atbash_selfinverse():
    assert atbash.decrypt(atbash.encrypt(PLAIN)) == PLAIN


def test_vigenere_roundtrip():
    assert vigenere.decrypt(vigenere.encrypt(PLAIN, "LEMON"), "LEMON") == PLAIN


def test_railfence_roundtrip():
    ct = transposition.rail_encrypt(PLAIN, 4)
    assert transposition.rail_decrypt(ct, 4) == PLAIN


def test_morse_roundtrip():
    assert morse.decode(morse.encode("HELLO WORLD")) == "HELLO WORLD"


def test_xor_roundtrip():
    key = b"KEY"
    assert xor.xor_bytes(xor.xor_bytes(b"hello world", key), key) == b"hello world"


# --------------------------- solvers -------------------------------------
def test_caesar_solve():
    ct = caesar.encrypt(PLAIN, 13)
    best = caesar.solve(ct, top=1)[0]
    assert best.plaintext == PLAIN and best.key == 13


def test_affine_solve():
    ct = affine.encrypt(PLAIN, 7, 3)
    best = affine.solve(ct, top=1)[0]
    assert best.plaintext == PLAIN


def test_vigenere_solve():
    ct = vigenere.encrypt(PLAIN, "SECRET")
    best = vigenere.solve(ct, top=1)[0]
    assert best.key == "SECRET"
    assert best.plaintext == PLAIN


def test_substitution_solve():
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    ct = substitution.apply_key(PLAIN, key)
    best = substitution.solve(ct, restarts=15, iterations=3000, top=1, seed=1)[0]
    # Allow a few mismatched rare letters; demand high recovery.
    matches = sum(a == b for a, b in zip(best.plaintext, PLAIN))
    assert matches / len(PLAIN) > 0.9


def test_xor_single_byte_solve():
    ct = xor.xor_bytes(PLAIN.encode(), b"\x42")
    best = xor.solve_single_byte(ct, top=1)[0]
    assert best.plaintext == PLAIN


def test_xor_repeating_solve():
    long_plain = (PLAIN + " " + PLAIN + " " + PLAIN).encode()
    ct = xor.xor_bytes(long_plain, b"KEY!")
    best = xor.solve_repeating_key(ct, top=1)[0]
    assert "quick brown fox" in best.plaintext


# --------------------------- encodings -----------------------------------
def test_recursive_decode():
    import base64
    layered = base64.b64encode("hello secret".encode().hex().encode()).decode()
    decoded, steps = encodings.recursive_decode(layered)
    assert decoded == "hello secret"
    assert steps == ["base64", "hex"]


# --------------------------- hashes --------------------------------------
def test_hash_identify():
    import hashlib
    h = hashlib.sha256(b"x").hexdigest()
    info = identify(h)
    assert "sha256" in info["candidates"] and info["attackable"]


def test_hash_dictionary():
    import hashlib
    h = hashlib.md5("Password123".encode()).hexdigest()
    result = crack_dictionary(h, ["letmein", "password", "admin"], algo="md5")
    assert result and result["plaintext"] == "Password123"


def test_bcrypt_not_attackable():
    info = identify("$2b$12$abcdefghijklmnopqrstuv")
    assert info["attackable"] is False


# --------------------------- end to end ----------------------------------
def test_auto_crack_caesar():
    ct = caesar.encrypt(PLAIN, 5)
    cands = auto_crack(ct, deep=False, top=5)
    assert any(c.plaintext == PLAIN for c in cands)


def test_auto_crack_vigenere():
    ct = vigenere.encrypt(PLAIN, "LEMON")
    cands = auto_crack(ct, deep=False, top=5)
    assert any("quick brown fox" in c.plaintext for c in cands)


def test_abbrev_expands_vowel_dropped_words():
    # Vowel-dropped common words should expand to the real word.
    assert "WORLD" in abbrev.expand_token("WLD") or \
           "WOULD" in abbrev.expand_token("WLD")
    assert "PLEASE" in abbrev.expand_token("PLSE")


def test_abbrev_analyze_is_honest():
    # On genuinely abbreviated English the analyzer finds strong matches but
    # never asserts a decoding; the report is evidence, not plaintext.
    rep = abbrev.analyze("WLD PLSE NMRSE CLTRSE FRTSE HTLSE")
    assert rep["strong_matches"] >= 4
    assert "expansions" in rep and "strong_fraction" in rep
    # Report contains no field that purports to be "the" decoded message.
    assert "plaintext" not in rep and "solution" not in rep


def test_abbrev_best_reading_picks_one_word():
    reading = abbrev.best_reading("WLD PLSE NMRSE")
    assert len(reading) == 1
    choices = [c["choice"] for c in reading[0]]
    assert choices[0] in ("WORLD", "WOULD", "WILD")
    assert choices[1] == "PLEASE"
    assert choices[2] == "NUMEROUS"


def test_abbrev_token_context():
    text = "AAA WLD NCBE\nBBB WLD NCBE\nCCC NCBE"
    ctx = abbrev.token_context(text, "NCBE")
    assert ctx["count"] == 3
    assert ctx["line_final"] == 3            # ends every line here
    assert dict(ctx["preceded_by"]).get("WLD") == 2
    assert ctx["vowel_insertion"] is None    # genuinely has no clean expansion


def test_addresses_detects_repeated_template():
    text = ("AAA PRSE ONE 71 NCBE\n"
            "BBB PRSE TWO 74 NCBE\n"
            "CCC PRSE SIX 75 NCBE\n"
            "random line here")
    rep = addresses.analyze(text)
    # The three parallel lines share one template, detected as structure.
    assert any(count == 3 for _, count in rep["repeated_templates"])
    assert len(rep["numbered_lines"]) == 3


def test_addresses_street_cross_check():
    assert "STREET" in addresses.street_match("STRT")   # consonant skeleton
    assert addresses.street_match("NCBE") == []          # no false positive


def test_units_finds_shared_substring_by_spread():
    # "ING" is shared across three distinct tokens -> high spread.
    rows = units.repeated_substrings("RUNNING JUMPING SINGING", min_count=3)
    by_sub = {s: (c, sp) for s, c, sp in rows}
    assert "ING" in by_sub and by_sub["ING"][1] == 3


def test_units_affix_habits():
    aff = units.affixes("CATSE DOGSE BIRDSE CARSE")
    assert aff["end_SE"] == 4 and aff["end_SE_fraction"] == 1.0
    assert units.stems("CATSE DOGSE", "SE") == ["CAT", "DOG"]


def test_phonetic_matches_by_sound():
    # 'NMBRS' (vowel-dropped, phonetic) should sound like NUMBERS.
    assert "NUMBERS" in phonetic.sound_matches("NMBRS")
    # sound folding: C/K merge, so 'KLR' reaches COLOR-class words.
    key_c = phonetic.sound_key("CLR")
    key_k = phonetic.sound_key("KLR")
    assert key_c == key_k            # C and K fold to the same sound


def test_cross_validate_reports_two_halves():
    text = ("# --- Page 1 ---\nCATSE DOGSE NCBE\n"
            "# --- Page 2 ---\nBIRDSE CARSE NCBE")
    cv = units.cross_validate(text)
    assert len(cv["halves"]) == 2
    assert cv["halves"][0]["NCBE"] == 1 and cv["halves"][1]["NCBE"] == 1


def test_rebus_reads_real_rebuses():
    assert rebus.best_reading("CU")[0] == "see you"
    assert rebus.best_reading("RU")[0] == "are you"
    assert rebus.best_reading("B4")[0] in ("be for", "be four")


def test_rebus_does_not_force_ncbe():
    # NCBE must not produce a confident single-word/coherent reading; the best
    # it yields is a run of tiny coincidental words.  We assert it is NOT a
    # clean one- or two-word reading.
    reading, _ = rebus.best_reading("NCBE")
    assert len(reading.split()) >= 3   # only decomposes into tiny pieces


def test_assess_reports_solved():
    ct = caesar.encrypt(PLAIN, 4)
    verdict = assess(ct)
    assert verdict["verdict"] == "solved"


def test_assess_reports_unsolved_on_gibberish():
    # Random letters+digits with no underlying English plaintext: the tool
    # must NOT claim a solution.  This guards the "never fake a break" promise.
    import random
    rng = random.Random(0)
    junk = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                   for _ in range(90))
    verdict = assess(junk)
    assert verdict["verdict"] == "unsolved"
    assert verdict["confidence"] < 0.48
    assert verdict["notes"]  # must explain what it sees instead of guessing


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
