import os
import time
import threading
from dataclasses import dataclass
from typing import Optional, Tuple, Dict

from flask import jsonify

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

@dataclass
class RateDecision:
    ok: bool
    retry_after_s: int = 0
    reason: str = ""

class AbuseGuard:
    """
    Lightweight, in-memory abuse mitigation.

    Goals (CTF-friendly):
    - discourage brute-force attempts with *progressive* slowdown
    - keep normal solver flows unaffected
    - avoid external dependencies (Redis, etc.)
    """
    def __init__(self):
        # Token-bucket rate limit (per IP, all endpoints).
        self.rate_per_min = _env_int("ABUSE_RATE_PER_MIN", 180)  # generous default
        self.burst = _env_int("ABUSE_BURST", max(30, self.rate_per_min // 2))
        self._fill_rate = float(self.rate_per_min) / 60.0  # tokens/sec

        # Failure penalty (per IP, per bucket).
        self.fail_base_delay_ms = _env_int("ABUSE_FAIL_BASE_DELAY_MS", 150)
        self.fail_max_delay_ms = _env_int("ABUSE_FAIL_MAX_DELAY_MS", 4000)
        self.fail_ban_after = _env_int("ABUSE_FAIL_BAN_AFTER", 40)
        self.fail_window_s = _env_int("ABUSE_FAIL_WINDOW_S", 600)
        self.fail_ban_s = _env_int("ABUSE_FAIL_BAN_S", 300)

        self._lock = threading.Lock()
        self._buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_ts)
        self._fails: Dict[Tuple[str, str], Tuple[int, float, float]] = {}  # (ip,bucket)->(count, first_ts, banned_until)

    def allow(self, ip: str) -> RateDecision:
        now = time.time()
        with self._lock:
            tokens, last = self._buckets.get(ip, (float(self.burst), now))
            # Refill
            tokens = min(float(self.burst), tokens + (now - last) * self._fill_rate)
            if tokens < 1.0:
                # Compute retry-after for a single token
                need = 1.0 - tokens
                retry = max(1, int(need / self._fill_rate + 0.999))
                self._buckets[ip] = (tokens, now)
                return RateDecision(ok=False, retry_after_s=retry, reason="rate_limited")
            tokens -= 1.0
            self._buckets[ip] = (tokens, now)
            return RateDecision(ok=True)

    def is_banned(self, ip: str, bucket: str) -> Optional[int]:
        now = time.time()
        with self._lock:
            key = (ip, bucket)
            if key not in self._fails:
                return None
            count, first, banned_until = self._fails[key]
            if banned_until > now:
                return int(banned_until - now)
            return None

    def penalize_failure(self, ip: str, bucket: str) -> float:
        """
        Record a failed attempt and return the delay (seconds) to apply.
        """
        now = time.time()
        with self._lock:
            key = (ip, bucket)
            count, first, banned_until = self._fails.get(key, (0, now, 0.0))

            # Reset if outside window
            if (now - first) > float(self.fail_window_s):
                count, first, banned_until = (0, now, 0.0)

            if banned_until > now:
                return 0.0

            count += 1

            # Ban threshold
            if count >= self.fail_ban_after:
                banned_until = now + float(self.fail_ban_s)

            self._fails[key] = (count, first, banned_until)

            # Exponential backoff, capped
            delay_ms = min(self.fail_max_delay_ms, int(self.fail_base_delay_ms * (2 ** max(0, count - 1))))
            return delay_ms / 1000.0

    def note_success(self, ip: str, bucket: str) -> None:
        # On success, clear failures for this bucket to avoid punishing correct flow.
        with self._lock:
            self._fails.pop((ip, bucket), None)

def client_ip(req) -> str:
    xf = req.headers.get("X-Forwarded-For")
    if xf:
        return xf.split(",")[0].strip()
    return (req.remote_addr or "unknown").strip()

def too_many_response(retry_after_s: int, reason: str = "rate_limited"):
    resp = jsonify(ok=False, error=reason)
    resp.status_code = 429
    resp.headers["Retry-After"] = str(int(retry_after_s))
    return resp
