#!/usr/bin/env python3
import os
import json
import csv
import time
import hashlib
import sqlite3
import subprocess
from pathlib import Path
from watchdog.observers import Observer
import errno
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler
import logging

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

DB = "/var/lib/tmc/tmc.db"
REPORT = "/var/lib/tmc/reports/image_context.csv"
USB = Path("/mnt/usb")
DCIM = USB/"DCIM"
LOGS = USB/"logs"
os.makedirs(DCIM, exist_ok=True)
os.makedirs(LOGS, exist_ok=True)
os.makedirs(os.path.dirname(REPORT), exist_ok=True)

with sqlite3.connect(DB) as conn:
    conn.execute("""create table if not exists images(
    id integer primary key, path text unique, file_type text, mime_type text, captured_at_utc text,
    gps_lat real, gps_lon real, camera_id text, sha256 text)""")

    # Use a new, richer table so we don't fight prior schema
    conn.execute("""create table if not exists timing_logs_v2(
    id integer primary key,
    ts_utc text, intersection_id text, mode text,
    ring1_phase integer, ring1_state text, ring1_elapsed_ms integer,
    ring2_phase integer, ring2_state text, ring2_elapsed_ms integer,
    p1 text,p2 text,p3 text,p4 text,p5 text,p6 text,p7 text,p8 text,
    event text
    )""")
    conn.execute("create index if not exists idx_tlv2_ts on timing_logs_v2(ts_utc)")

    conn.execute("""create table if not exists usb_events(
    id integer primary key, ts_utc text, path text, event text)""")

    conn.execute("""create table if not exists image_context(
    image_id integer primary key, timing_id integer, delta_s integer,
    foreign key(image_id) references images(id),
    foreign key(timing_id) references timing_logs_v2(id)
    )""")

    # View for easy human-readable joins
    conn.execute("""create view if not exists image_with_state as
    select i.id as image_id, i.path, i.captured_at_utc,
        t.ts_utc as state_ts, x.delta_s, t.mode,
        t.ring1_phase, t.ring1_state, t.ring2_phase, t.ring2_state,
        t.p1,t.p2,t.p3,t.p4,t.p5,t.p6,t.p7,t.p8, t.event
    from image_context x
    join images i on i.id = x.image_id
    join timing_logs_v2 t on t.id = x.timing_id""")
    conn.commit()

logging.info("Tables initialized")


def _norm_ts_sqlite(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip()
    # EXIF: 2025:08:12 14:37:25  ->  2025-08-12 14:37:25
    if len(s) >= 19 and s[4] == ':' and s[7] == ':':
        s = f"{s[0:4]}-{s[5:7]}-{s[8:10]} {s[11:19]}"
    # ISO8601Z: 2025-08-12T14:37:25Z  ->  2025-08-12 14:37:25
    s = s.replace('T', ' ').replace('Z', '')
    return s


def audit(event, p):
    with sqlite3.connect(DB) as conn:
        conn.execute(
            "insert into usb_events(ts_utc,path,event) values (datetime('now'),?,?)", (str(p), event))
        conn.commit()


def sha256sum(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()


def exif_extract(p):
    try:
        out = subprocess.check_output(
            ["exiftool", "-json", "-n", "-DateTimeOriginal",
                "-GPSLatitude", "-GPSLongitude", "-Model", 
                "-FileType", "-MIMEType", str(p)],
            stderr=subprocess.STDOUT
        )
        logging.info(f"exiftool out: {out}")
        d = json.loads(out)[0]
        logging.info(f"Retrieved exif data for {str(p)}: {d}")
        dt = _norm_ts_sqlite(d.get("DateTimeOriginal"))
        return (dt,
                d.get("GPSLatitude"), d.get("GPSLongitude"), d.get("Model"),
                d.get("FileType"), d.get("MIMEType"))
    except (subprocess.CalledProcessError, json.decoder.JSONDecodeError) as e:
        logging.error(f"Exiftool failed for {str(p)}: err={e}")
        return None, None, None, None, None, None


def insert_image(p):
    sha = sha256sum(p)
    dt, lat, lon, model, ftype, mtype = exif_extract(p)
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        INSERT OR IGNORE INTO images(path,captured_at_utc,gps_lat,gps_lon,camera_id,sha256,file_type,mime_type)
        VALUES (?,?,?,?,?,?,?,?)
        """, (str(p), dt, lat, lon, model, sha, ftype, mtype))
        conn.commit()

    # Try immediate correlation; if no timing yet, backfill will handle later
    if dt:
        img_id = conn.execute(
            "select id from images where path=?", (str(p),)).fetchone()
        if img_id:
            correlate_and_report(img_id[0], dt)


def parse_int(v):
    try:
        return int(v) if v not in (None, "") else None
    except:
        return None


def insert_timing_csv(p):
    with sqlite3.connect(DB) as conn:
        with open(p, newline='') as f:
            rdr = csv.DictReader(f)
            for r in rdr:
                conn.execute("""insert into timing_logs_v2(
                                    ts_utc,intersection_id,mode,
                                    ring1_phase,ring1_state,ring1_elapsed_ms,
                                    ring2_phase,ring2_state,ring2_elapsed_ms,
                                    p1,p2,p3,p4,p5,p6,p7,p8,event
                                ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    r.get("timestamp"), r.get("intersection_id"), r.get("mode"),
                    parse_int(r.get("ring1_phase")), r.get("ring1_state"), 
                    parse_int(r.get("ring1_elapsed_ms")),
                    parse_int(r.get("ring2_phase")), r.get("ring2_state"), 
                    parse_int(r.get("ring2_elapsed_ms")),
                    r.get("p1"), r.get("p2"), r.get("p3"), r.get("p4"),
                    r.get("p5"), r.get("p6"), r.get("p7"), r.get("p8"),
                    r.get("event")
                ))
        conn.commit()
    backfill_missing_context()


def insert_timing_jsonl(p):
    with sqlite3.connect(DB) as conn:
        with open(p) as f:
            for line in f:
                if not line.strip():
                    continue
                o = json.loads(line)
                vals = (
                    o.get("timestamp"), o.get("intersection_id"), o.get("mode"),
                    parse_int(o.get("ring1_phase")), o.get(
                        "ring1_state"), parse_int(o.get("ring1_elapsed_ms")),
                    parse_int(o.get("ring2_phase")), o.get(
                        "ring2_state"), parse_int(o.get("ring2_elapsed_ms")),
                    o.get("p1"), o.get("p2"), o.get("p3"), o.get("p4"),
                    o.get("p5"), o.get("p6"), o.get("p7"), o.get("p8"),
                    o.get("event")
                )
                conn.execute("""insert into timing_logs_v2(
                                ts_utc,intersection_id,mode,
                                ring1_phase,ring1_state,ring1_elapsed_ms,
                                ring2_phase,ring2_state,ring2_elapsed_ms,
                                p1,p2,p3,p4,p5,p6,p7,p8,event
                            ) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
        conn.commit()


def append_report(image_id: int):
    logging.info(f"Appending report for image {image_id}")
    with sqlite3.connect(DB) as conn:
        row = conn.execute(
            "select * from image_with_state where image_id=?", (image_id,)).fetchone()
        if not row:
            return
        # headers (once)
        if not os.path.exists(REPORT):
            headers = [d[1] for d in conn.execute(
                "pragma table_info('image_with_state')")]
            with open(REPORT, "w", newline='') as f:
                f.write(",".join(headers)+"\n")
        # append
        with open(REPORT, "a", newline='') as f:
            f.write(",".join("" if v is None else str(v) for v in row) + "\n")


def process(p: Path):
    if not p.is_file():
        logging.error(f"Could not process {p.absolute}. Is it a file?")
        return
    try:
        if p.parent == DCIM:
            logging.info(f"Processing image {p.absolute()}")
            insert_image(p)
            audit("image_ingested", p)
        elif p.parent == LOGS:
            s = p.suffix.lower()
            if s == ".csv":
                logging.info(f"Processing CSV log {p.absolute()}")
                insert_timing_csv(p)
                audit("log_csv_ingested", p)
            elif s in (".jsonl", ".ndjson"):
                logging.info(f"Processing json log {p.absolute()}")
                insert_timing_jsonl(p)
                audit("log_jsonl_ingested", p)
    except Exception as e:
        logging.error(f"Could not process {p.absolute()}: {e}")
        try:
            audit("error:"+repr(e), p)
        except Exception as e2:
            logging.error(f"audit() failed: {e2}")


def correlate_and_report(img_id: int, dt_utc_str: str, window_s: int = 5) -> bool:
    with sqlite3.connect(DB) as conn:
        norm_img = _norm_ts_sqlite(dt_utc_str)
        if not norm_img:
            logging.warning(f"Could not normalize time for image {img_id}")
            return False
        row = conn.execute("""
        SELECT id, ts_utc,
                ABS(
                strftime('%s', REPLACE(REPLACE(ts_utc,'T',' '),'Z','')) -
                strftime('%s', ?)
                ) AS delta_s
        FROM timing_logs_v2
        WHERE ts_utc IS NOT NULL
        ORDER BY (delta_s IS NULL), delta_s ASC
        LIMIT 1
        """, (norm_img,)).fetchone()
        if not row or row[2] is None or row[2] > window_s:
            logging.warning(f"Could not find log time for image {img_id}")
            return False
        conn.execute("REPLACE INTO image_context(image_id,timing_id,delta_s) VALUES (?,?,?)",
                    (img_id, row[0], row[2]))
        conn.commit()
        append_report(img_id)
        return True


def backfill_missing_context(window_s: int = 5):
    with sqlite3.connect(DB) as conn:
        for img_id, dt in conn.execute("""
            select i.id, i.captured_at_utc
            from images i
            left join image_context x on x.image_id = i.id
            where x.image_id is null and i.captured_at_utc is not null
        """):
            correlate_and_report(img_id, dt, window_s)


class Handler(FileSystemEventHandler):
    def on_created(self, e):
        process(Path(e.src_path))

    def on_moved(self, e):
        process(Path(e.dest_path))

    def on_modified(self, e):
        p = Path(e.src_path)
        try:
            if p.is_file() and p.stat().st_size < 32*1024*1024:
                process(p)
        except Exception as e:
            logging.error(f"on_modified({p}) failed: {e}")


def _make_observer(prefer_inotify: bool = True):
    return Observer() if prefer_inotify else PollingObserver(timeout=1.0)

def _start_observer(prefer_inotify: bool = True):
    obs = _make_observer(prefer_inotify=prefer_inotify)
    h = Handler()
    obs.schedule(h, str(DCIM), recursive=False)
    obs.schedule(h, str(LOGS), recursive=False)
    obs.start()
    return obs, prefer_inotify

if __name__ == "__main__":
    # Initial scan
    for d in (DCIM, LOGS):
        for p in d.glob('*'):
            process(p)
    try:
        for d in (DCIM, LOGS):
            for p in d.glob('*'):
                process(p)
        backfill_missing_context()
    except Exception as ex:
        logging.error(f"Startup backfill failed: {ex}")
    logging.info("Initial scan complete")

    # Watch (prefer inotify; fall back to polling on EMFILE / inotify limit)
    prefer_inotify = True
    try:
        obs, prefer_inotify = _start_observer(prefer_inotify=prefer_inotify)
    except OSError as e:
        if e.errno == errno.EMFILE:
            logging.error("inotify/FD limit hit (errno 24); falling back to polling observer")
            obs, prefer_inotify = _start_observer(prefer_inotify=False)
        else:
            raise

    try:
        while True:
            if not obs.is_alive():
                logging.error("Observer died; restarting after 5 seconds")
                obs.stop()
                obs.join(timeout=1)
                time.sleep(5)
                try:
                    obs, prefer_inotify = _start_observer(prefer_inotify=prefer_inotify)
                except OSError as e:
                    if e.errno == errno.EMFILE and prefer_inotify:
                        logging.error("inotify/FD limit hit (errno 24); switching to polling observer")
                        obs, prefer_inotify = _start_observer(prefer_inotify=False)
                    else:
                        raise
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
        obs.join()
