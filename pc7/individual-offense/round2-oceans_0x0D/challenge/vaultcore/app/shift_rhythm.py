from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import List, Optional

from .roulette import RouletteOutcome, spin as roulette_spin

log = logging.getLogger("vault.rhythm")

# Prime slots used as carriers. We use the first N primes depending on bits_per_bucket.
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61]

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    return int(v.strip())

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    if v is None:
        return default
    return float(v.strip())

def _env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    if v is None:
        return default
    return v

@dataclass(frozen=True)
class RhythmSettings:
    enable: bool = True
    bucket_seconds: int = 3
    spin_interval_ms: int = 600
    jitter_ms: int = 90

    bits_per_bucket: int = 32               # 32 bits → 4 bytes
    output_mode: str = "base32"             # "base32" or "hex"
    carrier_rule: str = "prime_slots"       # currently only this
    marker_pocket: str = "00"               # marker at slot=0

    noise_prob: float = 0.35                # probability a NON-carrier slot is random noise
    retained_beacon: bool = True            # retain the rhythm rules topic

    @staticmethod
    def from_env() -> "RhythmSettings":
        return RhythmSettings(
            enable=_env_bool("RHYTHM_ENABLE", True),
            bucket_seconds=_env_int("RHYTHM_BUCKET_SECONDS", 3),
            spin_interval_ms=_env_int("RHYTHM_SPIN_INTERVAL_MS", 600),
            jitter_ms=_env_int("RHYTHM_JITTER_MS", 90),
            bits_per_bucket=_env_int("RHYTHM_BITS_PER_BUCKET", 32),
            output_mode=_env_str("RHYTHM_OUTPUT_MODE", "base32"),
            carrier_rule=_env_str("RHYTHM_CARRIER_RULE", "prime_slots"),
            marker_pocket=_env_str("RHYTHM_MARKER_POCKET", "00"),
            noise_prob=_env_float("RHYTHM_NOISE_PROB", 0.35),
            retained_beacon=_env_bool("RHYTHM_RETAINED_BEACON", True),
        )

class ShiftRhythmEmitter:
    """
    Emits:
      - telemetry/roulette/rhythm  (retained rules beacon)
      - telemetry/roulette/spin    (continuous, includes bucket/slot, embeds bits on prime slots)

    Bit embedding:
      - slot 0 is always marker pocket (default "00")
      - carrier slots are primes: 2,3,5,7,... (first N based on bits_per_bucket)
      - bit = 1 => force odd pocket (red)
      - bit = 0 => force even pocket (black)
      - bucket bitstream comes from HMAC(secret, bucket_index)
    """

    def __init__(self, mqtt, settings: RhythmSettings, secret: bytes):
        self.mqtt = mqtt  # expects publish_json(suffix, obj, retain=?, qos=?)
        self.s = settings
        self.secret = secret

        self._task: Optional[asyncio.Task] = None
        self._rng = random.Random(int.from_bytes(hashlib.sha256(secret).digest()[:8], "big") ^ int(time.time()))

    def _bucket_index(self, now: float) -> int:
        return int(now // self.s.bucket_seconds)

    def _bucket_bits(self, bucket: int) -> List[int]:
        # HMAC-SHA256(secret, str(bucket)) -> take first bits_per_bucket bits (MSB-first)
        digest = hmac.new(self.secret, str(bucket).encode(), hashlib.sha256).digest()
        bits: List[int] = []
        for byte in digest:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
                if len(bits) >= self.s.bits_per_bucket:
                    return bits
        return bits

    def _carrier_slots(self) -> List[int]:
        """
        Returns the slot indices that carry bits for the current settings.
        Slot 0 is reserved for the marker.
        """
        if self.s.carrier_rule == "first_slots":
            # slots 1..N (skip marker at slot 0)
            return list(range(1, 1 + self.s.bits_per_bucket))
        # default: prime slots
        if self.s.bits_per_bucket > len(PRIMES):
            raise ValueError(
                f"bits_per_bucket={self.s.bits_per_bucket} exceeds PRIMES list length ({len(PRIMES)}). "
                "Either extend PRIMES or use RHYTHM_CARRIER_RULE=first_slots."
            )
        return PRIMES[: self.s.bits_per_bucket]



    def _choose_pocket_for_bit(self, bit: int) -> RouletteOutcome:
        # You requested: odd=red, even=black, "00" only green.
        # Choose a random odd/even number pocket to match bit.
        if bit == 1:
            pocket = str(self._rng.choice([n for n in range(1, 37) if n % 2 == 1]))
        else:
            pocket = str(self._rng.choice([n for n in range(1, 37) if n % 2 == 0]))

        # Map to outcome using your simplified schema
        n = int(pocket)
        parity = "odd" if (n % 2) else "even"
        color = "red" if parity == "odd" else "black"
        return RouletteOutcome(pocket=pocket, color=color, parity=parity)

    def _marker_outcome(self) -> RouletteOutcome:
        return RouletteOutcome(pocket=self.s.marker_pocket, color="green", parity=None)

    async def start(self) -> None:
        if not self.s.enable or self._task:
            return
        self._task = asyncio.create_task(self._run_supervised(), name="shift_rhythm")

    async def _run_supervised(self) -> None:
        while True:
            try:
                await self._run()
            except Exception:
                log.exception("shift_rhythm_crashed_restart")
                await asyncio.sleep(2)

    async def _publish_rules_beacon(self) -> None:
        carriers = self._carrier_slots()

        beacon = {
            "v": 2,
            "bucket_seconds": self.s.bucket_seconds,
            "bits_per_bucket": self.s.bits_per_bucket,
            "carrier_rule": self.s.carrier_rule,
            "carrier_slots": carriers,   # ← THIS is the fix
            "encoding": "parity",
            "bit_mapping": {"odd": 1, "even": 0},
            "marker": {"slot": 0, "pocket": self.s.marker_pocket},
            "spin_interval_ms": self.s.spin_interval_ms,
            "jitter_ms": self.s.jitter_ms,
            "output_mode": self.s.output_mode,
            "ts": int(time.time() * 1000),
        }

        await self.mqtt.publish_json(
            "telemetry/roulette/rhythm",
            beacon,
            retain=self.s.retained_beacon,
        )


    async def _run(self) -> None:
        await self._publish_rules_beacon()

        last_bucket = None
        slot = 0
        bucket_bits: List[int] = []
        carriers: List[int] = []

        while True:
            now = time.time()
            b = self._bucket_index(now)

            if b != last_bucket:
                last_bucket = b
                slot = 0
                bucket_bits = self._bucket_bits(b)

                # 🔧 FIX: use carrier rule (first_slots or primes)
                carriers = self._carrier_slots()

                await self._publish_rules_beacon()

            # Determine outcome
            marker = False
            if slot == 0:
                out = self._marker_outcome()
                marker = True
            elif slot in carriers:
                bit_index = carriers.index(slot)
                out = self._choose_pocket_for_bit(bucket_bits[bit_index])
            else:
                # noise: sometimes true random, sometimes plausible “house” bias
                if self._rng.random() < self.s.noise_prob:
                    out = roulette_spin()  # random but consistent schema
                else:
                    # mild bias: avoid green except marker
                    out = self._choose_pocket_for_bit(self._rng.randint(0, 1))

            payload = {
                "bucket": b,
                "slot": slot,
                "marker": marker,
                "pocket": out.pocket,
                "color": out.color,
                "parity": out.parity,
                "ts": int(now * 1000),
            }

            await self.mqtt.publish_json("telemetry/roulette/spin", payload, retain=False)

            slot += 1
            base = self.s.spin_interval_ms / 1000.0
            jitter = self._rng.uniform(-self.s.jitter_ms, self.s.jitter_ms) / 1000.0
            await asyncio.sleep(max(0.10, base + jitter))

    # Helper a server-side verifier could use (optional)
    def expected_code_for_bucket(self, bucket: int) -> str:
        bits = self._bucket_bits(bucket)

        # pack bits into bytes
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
            out.append(byte)

        if self.s.output_mode == "hex":
            return out.hex()
        # base32 without padding, uppercase for human typing
        return base64.b32encode(bytes(out)).decode().rstrip("=").upper()

