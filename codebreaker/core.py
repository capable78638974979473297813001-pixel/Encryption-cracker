"""Shared types used across the toolkit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(order=True)
class Candidate:
    """A single candidate decryption produced by a solver."""

    score: float                                 # higher = better (sorts first)
    cipher: str = field(compare=False)           # e.g. "caesar"
    plaintext: str = field(compare=False)
    key: Any = field(default=None, compare=False)
    confidence: float = field(default=0.0, compare=False)   # 0..1, English-ness
    meta: Dict[str, Any] = field(default_factory=dict, compare=False)

    def key_str(self) -> str:
        k = self.key
        if k is None:
            return ""
        if isinstance(k, (list, tuple)):
            return "".join(map(str, k)) if all(
                isinstance(x, str) for x in k) else str(list(k))
        return str(k)
