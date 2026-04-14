# challenge/vaultcore/app/mqtt_client.py
from __future__ import annotations
import asyncio
import json
import logging
import socket
import time

log = logging.getLogger("vault.mqtt")

try:
    from aiomqtt import Client, MqttError
except ImportError:
    from asyncio_mqtt import Client, MqttError


def resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    return infos[0][4][0]


class MqttClient:
    def __init__(self, host: str, port: int, client_id: str, base_topic: str, keepalive: int = 60):
        self.host = host
        self.port = port
        self.client_id = client_id
        self.base_topic = base_topic.rstrip("/")
        self.keepalive = keepalive

        self._client: Client | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        while True:
            try:
                ip = resolve_ipv4(self.host)
                log.info("mqtt_connecting", extra={"host": self.host, "ip": ip, "port": self.port})

                self._client = Client(
                    hostname=ip,
                    port=self.port,
                    identifier=self.client_id,
                    keepalive=self.keepalive,
                )

                await self._client.__aenter__()
                log.info("mqtt_connected", extra={"host": self.host, "ip": ip})
                return

            except Exception as e:
                log.warning("mqtt_connect_failed", extra={"err": str(e)})
                await asyncio.sleep(2)

    async def publish(self, topic: str, payload: dict, retain: bool = False, qos: int = 0) -> None:
        if not self._client:
            raise RuntimeError("MQTT client not started")

        full_topic = f"{self.base_topic}/{topic.lstrip('/')}"
        data = json.dumps(payload, separators=(",", ":"))

        async with self._lock:
            try:
                await self._client.publish(full_topic, data, qos=qos, retain=retain)
            except MqttError as e:
                log.error("mqtt_publish_failed", extra={"topic": full_topic, "err": str(e)})
                raise

    async def publish_json(self, topic: str, obj: dict, retain: bool = False, qos: int = 0) -> None:
        """
        Compatibility shim for modules that expect publish_json().
        Uses the same semantics as publish(): dict -> JSON string published to base_topic/topic
        """
        await self.publish(topic, obj, retain=retain, qos=qos)

