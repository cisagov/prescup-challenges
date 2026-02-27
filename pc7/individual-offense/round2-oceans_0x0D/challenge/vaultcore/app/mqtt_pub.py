from __future__ import annotations
import socket
import asyncio, json, logging
from dataclasses import dataclass
from aiomqtt import Client, MqttError
import os, socket


log = logging.getLogger("vault.mqtt")

@dataclass(frozen=True)
class MqttConfig:
    host: str
    port: int
    client_id: str
    keepalive: int
    base_topic: str

# IP resolutions
def _resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    return infos[0][4][0]

def _tcp_probe(ip: str, port: int) -> None:
    # small blocking probe; we’ll run it in a thread
    with socket.create_connection((ip, port), timeout=2):
        return

class MqttPublisher:
    def __init__(self, cfg: MqttConfig):
        self.cfg = cfg
        self._queue: asyncio.Queue[tuple[str, bytes, int, bool]] = asyncio.Queue(maxsize=6000)
        self._task: asyncio.Task | None = None

    async def start(self):
        if getattr(self, "_task", None):
            return  # already started

        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        backoff = 1.0
        attempts = int(os.getenv("MQTT_CONNECT_ATTEMPTS", "0"))  # 0 = infinite
        sleep_s = float(os.getenv("MQTT_CONNECT_SLEEP", "2"))

        tries = 0
        while True:
            try:
                # 1) DNS resolve (can fail early in container boot)
                ip = _resolve_ipv4(self.cfg.host)

                # 2) TCP readiness probe (like your arecibo)
                await asyncio.to_thread(_tcp_probe, ip, self.cfg.port)

                log.info("mqtt_connecting", extra={"host": self.cfg.host, "ip": ip, "port": self.cfg.port})

                # 3) Connect using resolved IP (reduces DNS dependence)
                async with Client(hostname=ip, port=self.cfg.port, identifier=self.cfg.client_id, keepalive=self.cfg.keepalive) as c:
                    log.info("mqtt_connected", extra={"host": self.cfg.host, "ip": ip, "port": self.cfg.port})
                    backoff = 1.0
                    tries = 0

                    while True:
                        topic, payload, qos, retain = await self._queue.get()
                        await c.publish(topic, payload, qos=qos, retain=retain)

            except (socket.gaierror, OSError) as e:
                # DNS not ready or TCP refused
                tries += 1
                log.warning("mqtt_broker_not_ready", extra={"err": str(e), "host": self.cfg.host, "port": self.cfg.port, "sleep": sleep_s, "try": tries})
                if attempts and tries >= attempts:
                    log.error("mqtt_broker_unreachable_fatal", extra={"host": self.cfg.host, "port": self.cfg.port})
                    await asyncio.sleep(999999)  # or sys.exit(1) if you prefer hard-fail
                await asyncio.sleep(sleep_s)

            except MqttError as e:
                log.warning("mqtt_disconnected", extra={"err": str(e), "backoff": backoff})
                await asyncio.sleep(backoff)
                backoff = min(backoff * 1.7, 15.0)

    async def publish_json(self, suffix: str, obj: dict, qos: int = 0, retain: bool = False) -> None:
        topic = f"{self.cfg.base_topic}/{suffix}"
        payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        await self.publish_raw(topic, payload, qos=qos, retain=retain)

    async def publish_raw(self, topic: str, payload: bytes, qos: int = 0, retain: bool = False) -> None:
        try:
            self._queue.put_nowait((topic, payload, qos, retain))
        except asyncio.QueueFull:
            try:
                _ = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self._queue.put_nowait((topic, payload, qos, retain))
