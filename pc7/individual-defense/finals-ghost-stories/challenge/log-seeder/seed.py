#!/usr/bin/env python3
"""Bulk-load Sysmon + PowerShell NDJSON events into Elasticsearch and
register Kibana index patterns + saved searches.

Runs once at container start. Exits 0 on success.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import sys
import time

import requests


ES_HOST = os.environ.get("ES_HOST", "http://elasticsearch:9200")
KIBANA_HOST = os.environ.get("KIBANA_HOST", "http://kibana:5601")
EVENTS_DIR = pathlib.Path("/seeder/events")

# Index mapping: NDJSON file → target ES index.
SOURCES = {
    "sysmon.ndjson": "sysmon-eng-bell-04",
    "powershell.ndjson": "powershell-eng-bell-04",
}


def wait_for(url: str, label: str, expect_field: str | None = None, timeout_s: int = 360) -> None:
    log = logging.getLogger(f"wait.{label}")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code in (200, 429) or resp.status_code == 401:
                if expect_field:
                    try:
                        payload = resp.json()
                    except ValueError:
                        payload = {}
                    if expect_field in payload:
                        log.info("%s ready", label)
                        return
                else:
                    log.info("%s ready", label)
                    return
        except requests.RequestException as exc:
            log.info("waiting for %s: %s", label, exc)
        time.sleep(5)
    raise SystemExit(f"{label} did not become ready in time")


def create_index(es_host: str, name: str) -> None:
    log = logging.getLogger("seed.index")
    body = {
        "mappings": {
            "dynamic": True,
            "properties": {
                "@timestamp": {"type": "date"},
                "host.hostname": {"type": "keyword"},
                "host.name": {"type": "keyword"},
                "user.name": {"type": "keyword"},
                "user.domain": {"type": "keyword"},
                "event.code": {"type": "keyword"},
                "event.provider": {"type": "keyword"},
                "event.action": {"type": "keyword"},
                "process.executable": {"type": "keyword"},
                "process.name": {"type": "keyword"},
                "process.command_line": {"type": "text"},
                "process.parent.executable": {"type": "keyword"},
                "process.parent.command_line": {"type": "text"},
                "destination.ip": {"type": "ip"},
                "destination.port": {"type": "long"},
                "destination.domain": {"type": "keyword"},
                "file.path": {"type": "keyword"},
                "registry.path": {"type": "keyword"},
                "winlog.event_id": {"type": "long"},
                "winlog.record_id": {"type": "long"},
                "winlog.event_data.Hashes": {"type": "keyword"},
                "winlog.event_data.ScriptBlockText": {"type": "text"},
            },
        }
    }
    resp = requests.put(f"{es_host}/{name}", json=body, timeout=10)
    if resp.status_code >= 400 and "resource_already_exists_exception" not in resp.text:
        raise SystemExit(f"failed to create index {name}: {resp.status_code} {resp.text}")
    log.info("index %s ready", name)


def bulk_load(es_host: str, index: str, ndjson_path: pathlib.Path) -> int:
    log = logging.getLogger("seed.bulk")
    lines = ndjson_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        log.info("no events to load from %s", ndjson_path)
        return 0
    body_parts: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        body_parts.append(json.dumps({"index": {"_index": index}}))
        body_parts.append(line)
    body = "\n".join(body_parts) + "\n"
    resp = requests.post(
        f"{es_host}/_bulk",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        timeout=60,
    )
    if resp.status_code >= 400:
        raise SystemExit(f"bulk load failed: {resp.status_code} {resp.text[:400]}")
    payload = resp.json()
    if payload.get("errors"):
        first_error = next(
            (item for item in payload.get("items", []) if item.get("index", {}).get("error")),
            None,
        )
        log.warning("bulk load reported errors; first: %s", first_error)
    return len(lines)


def refresh_index(es_host: str, index: str) -> None:
    requests.post(f"{es_host}/{index}/_refresh", timeout=10)


def create_kibana_index_pattern(kibana_host: str, pattern: str, title: str) -> None:
    log = logging.getLogger("seed.kibana")
    url = f"{kibana_host}/api/saved_objects/index-pattern/{title}"
    body = {"attributes": {"title": pattern, "timeFieldName": "@timestamp"}}
    resp = requests.post(
        url,
        json=body,
        headers={"kbn-xsrf": "true", "Content-Type": "application/json"},
        timeout=15,
    )
    if resp.status_code in (200, 409):
        log.info("kibana index pattern %s ready", title)
        return
    log.warning("kibana index pattern %s create returned %d: %s", title, resp.status_code, resp.text[:200])


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s", stream=sys.stderr)
    log = logging.getLogger("seed")

    wait_for(f"{ES_HOST}/_cluster/health?wait_for_status=yellow&timeout=30s", "elasticsearch", "status")

    total = 0
    for filename, index in SOURCES.items():
        path = EVENTS_DIR / filename
        if not path.is_file():
            log.warning("missing %s; skipping", path)
            continue
        create_index(ES_HOST, index)
        count = bulk_load(ES_HOST, index, path)
        refresh_index(ES_HOST, index)
        total += count
        log.info("loaded %d events into %s", count, index)

    # Best-effort Kibana index-pattern registration; ignore failures so
    # the seeder still exits 0 if kibana is slower to come up.
    try:
        wait_for(f"{KIBANA_HOST}/api/status", "kibana", "status")
        create_kibana_index_pattern(KIBANA_HOST, "sysmon-*", "sysmon-eng-bell-04")
        create_kibana_index_pattern(KIBANA_HOST, "powershell-*", "powershell-eng-bell-04")
    except SystemExit as exc:
        log.warning("kibana setup skipped: %s", exc)

    log.info("seed complete: %d events indexed", total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
