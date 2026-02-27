from __future__ import annotations
import time
from dataclasses import dataclass, field
from collections import deque

@dataclass
class DashboardState:
    degraded: bool = True
    alert_level: int = 0
    alert_state: str = "NORMAL"
    alert_score: float = 0.0
    lockdown_until: int = 0

    token1_found: bool = False
    token1_found_at: int = 0
    token1_reveal_until: int = 0
    token1_value: str = ""

    token2_found: bool = False
    token2_found_at: int = 0
    token2_reveal_until: int = 0
    token2_value: str = ""

    token3_found: bool = False
    token3_found_at: int = 0
    token3_reveal_until: int = 0
    token3_value: str = ""

    token4_found: bool = False
    token4_found_at: int = 0
    token4_reveal_until: int = 0
    token4_value: str = ""

    events: deque = field(default_factory=lambda: deque(maxlen=250))

    def as_public(self) -> dict:
        now = int(time.time())
        def visible(until, val):
            return val if (val and now <= until) else ""
        return {
            "ts": now,
            "degraded": self.degraded,
            "alert": {"level": self.alert_level, "state": self.alert_state, "score": self.alert_score, "lockdown_until": self.lockdown_until},
            "tokens": {
                "token1": {
                    "found": self.token1_found,
                    "found_at": self.token1_found_at,
                    "visible": bool(self.token1_value) and time.time() < self.token1_reveal_until,
                    "value": self.token1_value if time.time() < self.token1_reveal_until else None,
                },
                "token2": {
                    "found": self.token2_found,
                    "found_at": self.token2_found_at,
                    "visible": bool(self.token2_value) and time.time() < self.token2_reveal_until,
                    "value": self.token2_value if time.time() < self.token2_reveal_until else None,
                },
                "token3": {
                    "found": self.token3_found,
                    "found_at": self.token3_found_at,
                    "visible": bool(self.token3_value) and time.time() < self.token3_reveal_until,
                    "value": self.token3_value if time.time() < self.token3_reveal_until else None,
                },
                "token4": {
                    "found": self.token4_found,
                    "found_at": self.token4_found_at,
                    "visible": bool(self.token4_value) and time.time() < self.token4_reveal_until,
                    "value": self.token4_value if time.time() < self.token4_reveal_until else None,
                },
            },
            "events": list(self.events),
        }
