# challenge/vaultcore/app/telemetry.py
from __future__ import annotations
import asyncio
import logging
import random
import time

from .mqtt_client import MqttClient
from .mqtt_topics import telemetry, meta
from .roulette import spin as roulette_spin

log = logging.getLogger("vault.telemetry")


class CasinoTelemetry:
    def __init__(self, mqtt: MqttClient, interval: float = 1.0):
        self.mqtt = mqtt
        self.interval = interval
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if self._task:
            return
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        log.info("telemetry_started")

        # retained heartbeat so solvers *always* see something
        await self.mqtt.publish(
            meta("up"),
            {"service": "vaultcore", "ts": int(time.time())},
            retain=True,
        )

        while True:
            out = roulette_spin()
            payload = {
                "pocket": out.pocket,
                "color": out.color,
                "parity": out.parity,
                "ts": int(time.time() * 1000),
            }
            try:
                await self.mqtt.publish(
                    telemetry("roulette/spin"),
                    payload,
                    retain=False,
                )
            except Exception:
                log.exception("telemetry_publish_error")

            await asyncio.sleep(self.interval)

