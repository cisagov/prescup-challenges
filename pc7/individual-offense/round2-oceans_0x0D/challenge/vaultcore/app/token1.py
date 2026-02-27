from __future__ import annotations
import asyncio, hmac, hashlib, logging, math, random, time
from .alert import AlertEngine
from .mqtt_pub import MqttPublisher
from .state import VaultState
from .roulette import spin as roulette_spin

log = logging.getLogger("vault.token1")

def bucket_id(now: float, bucket_seconds: int) -> int:
    return int(math.floor(now / bucket_seconds))

def rhythm_sig(master: bytes, epoch_seed: bytes, bucket: int, out_bytes: int) -> bytes:
    msg = b"T1|RH|" + str(bucket).encode() + b"|" + epoch_seed
    return hmac.new(master, msg, hashlib.sha256).digest()[:out_bytes]

class Token1Emitter:
    def __init__(
        self,
        vault_state: VaultState,
        mqtt: MqttPublisher,
        alert: AlertEngine,
        base_topic: str,
        bucket_seconds: int,
        sig_bytes: int,
        bitrate_bpm: int,
        jitter_ms: int,
        noise_rate_per_sec: int,
        decoy_strength: int,
        encoding_mode: str,
    ):
        self.vault_state = vault_state
        self.mqtt = mqtt
        self.alert = alert
        self.base_topic = base_topic.rstrip("/")
        self.bucket_seconds = bucket_seconds
        self.sig_bytes = sig_bytes
        self.bitrate_bpm = bitrate_bpm
        self.jitter_ms = jitter_ms
        self.noise_rate_per_sec = noise_rate_per_sec
        self.decoy_strength = decoy_strength
        self.encoding_mode = encoding_mode
        self._task = None
        self._noise_task = None

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._emit_loop())
        if self._noise_task is None:
            self._noise_task = asyncio.create_task(self._noise_loop())

    async def _noise_loop(self) -> None:
        topics = [
            f"telemetry/slots",
            f"telemetry/camera",
            f"telemetry/cage",
        ]
        while True:
            rate = max(0, self.noise_rate_per_sec)
            if rate == 0:
                await asyncio.sleep(1.0)
                continue
            for _ in range(rate):
                t = random.choice(topics).replace(self.base_topic + "/", "")
                payload = {"ts": int(time.time()*1000), "id": random.randint(1000,9999), "stat": random.randint(0,100), "ok": True}
                await self.mqtt.publish_json(t, payload, qos=0, retain=False)
                await asyncio.sleep(1.0 / rate)

    async def _emit_loop(self) -> None:
        assert self.vault_state.secrets is not None
        retained_suffix = "telemetry/roulette/retained"
        spin_suffix = "telemetry/roulette/spin"
        bits_per_sec = max(1.0, self.bitrate_bpm / 60.0)
        bit_interval = 1.0 / bits_per_sec
        cursor = 0

        while True:
            now = time.time()
            b = bucket_id(now, self.bucket_seconds)
            sig = rhythm_sig(self.vault_state.secrets.master_secret, self.vault_state.secrets.epoch_seed, b, self.sig_bytes)

            sig_bits = []
            for byte in sig:
                for i in range(8):
                    sig_bits.append((byte >> (7 - i)) & 1)

            bit = sig_bits[cursor % len(sig_bits)]
            cursor += 1

            snap = await self.alert.snapshot()
            decoy_flip = 0
            if self.decoy_strength > 0:
                if self.decoy_strength == 1:
                    decoy_flip = 1 if (cursor % 17 == 0) else 0
                elif self.decoy_strength == 2:
                    decoy_flip = 1 if (cursor % (9 + snap.level) == 0) else 0
                else:
                    decoy_flip = 1 if (cursor % (5 + snap.level) in (0,1)) else 0

            observed_bit = bit ^ decoy_flip

            out = roulette_spin()
            await self.mqtt.publish_json(
                spin_suffix,
                {
                    "ts": int(now * 1000),
                    "bucket": b,
                    "slot": cursor % len(sig_bits),
                    "pocket": out.pocket,
                    "color": out.color,
                    "parity": out.parity,
    #               "phase": cursor % 360,
                    "rhythm_bit": observed_bit,
                },
                qos=0,
                retain=False,
            )            
            
            await self.mqtt.publish_json(retained_suffix, {"ts": int(now*1000), "v": random.randint(10000,99999)}, qos=0, retain=True)

            if self.encoding_mode in ("timing", "hybrid") and observed_bit == 1:
                await asyncio.sleep(self.jitter_ms / 1000.0)
                await self.mqtt.publish_json(retained_suffix, {"ts": int(time.time()*1000), "v": random.randint(10000,99999)}, qos=0, retain=True)

            await asyncio.sleep(bit_interval)
