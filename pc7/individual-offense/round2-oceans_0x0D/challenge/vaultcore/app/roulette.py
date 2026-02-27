# -*- coding: utf-8 -*-
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class RouletteOutcome:
    pocket: str            # "00" or "1".."36"
    color: str             # "green", "red", "black"
    parity: Optional[str]  # None for "00", else "odd"/"even"

def spin() -> RouletteOutcome:
    """
    Simplified roulette schema (as requested):
      - "00" is the ONLY green pocket
      - red = odd numbers
      - black = even numbers
    Notes:
      - Pocket set is {"00"} ∪ {1..36}. There is no "0" pocket.
    """
    pocket = random.choice(["00"] + [str(n) for n in range(1, 37)])
    if pocket == "00":
        return RouletteOutcome(pocket="00", color="green", parity=None)

    n = int(pocket)
    parity = "odd" if (n % 2 == 1) else "even"
    color = "red" if parity == "odd" else "black"
    return RouletteOutcome(pocket=pocket, color=color, parity=parity)

