"""International Morse code encode/decode."""

from __future__ import annotations

_MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..",
    "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-",
    "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.",
    "-": "-....-", "_": "..--.-", '"': ".-..-.", "@": ".--.-.", " ": "/",
}
_REV = {v: k for k, v in _MORSE.items()}


def encode(text: str) -> str:
    return " ".join(_MORSE.get(c.upper(), "") for c in text).strip()


def decode(morse: str) -> str:
    morse = morse.strip().replace("|", "/")
    # Support word separators of "/" or multiple spaces.
    words = morse.replace("   ", " / ").split(" / ")
    out_words = []
    for word in words:
        letters = [tok for tok in word.split(" ") if tok]
        out_words.append("".join(_REV.get(l, "") for l in letters))
    return " ".join(w for w in out_words if w)


def looks_like_morse(text: str) -> bool:
    stripped = set(text.strip())
    return stripped and stripped <= set(".-/ |\t\n")
