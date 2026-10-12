"""List / address-structure analysis.

The FBI's analysts pursued the idea that parts of the McCormick notes encode a
list — possibly St. Louis street addresses — because several lines share a
repeated template and end in a two-digit number.  This module tests that
hypothesis honestly:

1. **Template detection** — collapse each line to a shape (recurring tokens
   kept literally, other words -> W, numbers -> N) and find repeated shapes.
   Repeated shapes are real evidence of list/table structure.
2. **Street-vocabulary cross-check** — match each token's consonant skeleton
   against the USPS street-suffix and directional vocabulary, to see whether
   the recurring units could be street types/directions.

It reports structure and matches; it does not assert that any line *is* an
address.  A negative result (no street-vocabulary match) is reported as such,
not papered over.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List, Tuple

from .abbrev import _line_tokens, consonant_skeleton

# USPS-style street suffix full words and common address/directional words.
STREET_TYPES = [
    "STREET", "AVENUE", "BOULEVARD", "DRIVE", "ROAD", "LANE", "COURT", "PLACE",
    "CIRCLE", "TERRACE", "PARKWAY", "HIGHWAY", "PLAZA", "SQUARE", "TRAIL",
    "WAY", "PIKE", "ALLEY", "CROSSING", "PASS", "PATH", "RIDGE", "HILL",
    "HILLS", "PARK", "ROW", "POINT", "CREEK", "HOLLOW", "BEND", "LOOP", "WALK",
    "RUN", "MANOR", "HEIGHTS", "ESTATES", "LANDING", "COMMONS",
]
DIRECTIONALS = ["NORTH", "SOUTH", "EAST", "WEST", "NORTHEAST", "NORTHWEST",
                "SOUTHEAST", "SOUTHWEST"]
ADDRESS_WORDS = ["APARTMENT", "APT", "UNIT", "SUITE", "BOX", "ROUTE", "FLOOR",
                 "BUILDING", "BLOCK"]

_ADDR_VOCAB = STREET_TYPES + DIRECTIONALS + ADDRESS_WORDS
_ADDR_BY_SK: Dict[str, List[str]] = {}
for _w in _ADDR_VOCAB:
    _ADDR_BY_SK.setdefault(consonant_skeleton(_w), []).append(_w)


def street_match(token: str) -> List[str]:
    """Street-vocabulary words whose consonant skeleton matches ``token``."""
    return _ADDR_BY_SK.get(consonant_skeleton(token), [])


def _line_shape(line: List[str], recurring: set) -> Tuple[str, ...]:
    shape = []
    for t in line:
        if re.match(r"\d", t):
            shape.append("N")
        elif t in recurring:
            shape.append(t)
        else:
            shape.append("W")
    return tuple(shape)


def analyze(text: str) -> Dict:
    lines = _line_tokens(text)
    tokens = [t for line in lines for t in line]
    freq = Counter(tokens)
    recurring = {t for t, c in freq.items() if c >= 3 and t.isalpha()}

    # Repeated line templates (list/table structure).
    shapes = Counter(_line_shape(line, recurring) for line in lines)
    repeated = [(list(sh), c) for sh, c in shapes.most_common()
                if c >= 2 and any(x == "N" for x in sh)]

    # Lines that contain a number (candidate list entries).
    numbered = []
    for line in lines:
        nums = [t for t in line if re.match(r"\d", t)]
        if nums:
            numbered.append({"line": line, "numbers": nums,
                             "shape": list(_line_shape(line, recurring))})

    # Street-vocabulary hits across all tokens.
    street_hits = {}
    for t in sorted(set(t for t in tokens if t.isalpha())):
        m = street_match(t)
        if m:
            street_hits[t] = m

    return {
        "repeated_templates": repeated,
        "numbered_lines": numbered,
        "street_vocab_hits": street_hits,
        "numbers": [t for t in tokens if re.match(r"\d", t)],
    }
