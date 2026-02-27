from __future__ import annotations
import asyncio, logging, time
from dataclasses import dataclass

log = logging.getLogger("vault.alert")

@dataclass
class AlertSnapshot:
    score: float
    level: int
    state: str
    lockdown_until_ts: int

class AlertEngine:
    def __init__(self, decay_per_sec: float, thresholds: list[int], level5_mode: str, lockdown_seconds: int):
        self.decay_per_sec = decay_per_sec
        self.thresholds = thresholds
        self.level5_mode = level5_mode
        self.lockdown_seconds = lockdown_seconds
        self._score = 0.0
        self._lockdown_until_ts = 0
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._tick_loop())

    def _derive_level(self, score: float) -> int:
        lvl = 0
        for i, th in enumerate(self.thresholds):
            if score >= th:
                lvl = i
        return min(lvl, 5)

    def _derive_state(self, level: int) -> str:
        return ["NORMAL","GUARDED","ELEVATED","HIGH","CRITICAL","LOCKDOWN"][level]

    async def _tick_loop(self) -> None:
        last = time.time()
        while True:
            await asyncio.sleep(1.0)
            now = time.time()
            dt = now - last
            last = now
            async with self._lock:
                self._score = max(0.0, self._score - self.decay_per_sec * dt)
                if self._lockdown_until_ts and int(time.time()) >= self._lockdown_until_ts:
                    self._lockdown_until_ts = 0

    async def penalize(self, amount: float, reason: str) -> AlertSnapshot:
        # IMPORTANT: do not call snapshot() while holding _lock; snapshot() also acquires _lock.
        # That pattern deadlocks and will hang the entire API under bad inputs.
        async with self._lock:
            self._score += amount
            level = self._derive_level(self._score)
            if level >= 5:
                self._lockdown_until_ts = int(time.time()) + (10**9 if self.level5_mode == "lockdown" else self.lockdown_seconds)
            snap = AlertSnapshot(
                score=self._score,
                level=level,
                state=self._derive_state(level),
                lockdown_until_ts=self._lockdown_until_ts,
            )
        # Log outside lock to keep the hot path snappy.
        log.info("alert_penalty", extra={"amount": amount, "reason": reason, "level": snap.level, "score": snap.score})
        return snap

    async def snapshot(self) -> AlertSnapshot:
        async with self._lock:
            level = self._derive_level(self._score)
            return AlertSnapshot(score=self._score, level=level, state=self._derive_state(level), lockdown_until_ts=self._lockdown_until_ts)

    async def is_locked_down(self) -> bool:
        async with self._lock:
            return self._lockdown_until_ts > int(time.time())

