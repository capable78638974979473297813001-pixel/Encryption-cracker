"""codebreaker — a practical classical-cryptanalysis toolkit.

Public API re-exports the most useful entry points.  See the ``cli`` module
for the command-line interface and the README for scope and limits.
"""

from __future__ import annotations

from .analysis import (index_of_coincidence, kasiski_examination,
                       shannon_entropy)
from .core import Candidate
from .detect import auto_crack, profile

__version__ = "1.0.0"

__all__ = [
    "auto_crack", "profile", "Candidate",
    "index_of_coincidence", "kasiski_examination", "shannon_entropy",
    "__version__",
]
