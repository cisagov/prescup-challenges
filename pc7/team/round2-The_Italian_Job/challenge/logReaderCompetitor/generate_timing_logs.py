#!/usr/bin/env python3
import argparse
import csv
from datetime import datetime, timedelta, timezone

# ---------- Helpers ----------

def parse_iso_z(s: str) -> datetime:
    s = s.strip()
    # Accept Zulu 'Z' or explicit offset; store as UTC
    if s.endswith('Z'):
        dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    else:
        # Try without Z; assume UTC if no offset provided
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
        except Exception:
            dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return dt

def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def clamp(x, lo, hi):
    return lo if x < lo else hi if x > hi else x

# ---------- Generator ----------

def generate(
    out_path: str,
    intersection_id: int,
    start_utc: datetime,
    hours: float,
    accident_utc: datetime,
    flash_delay_s: int,
    flash_duration_s: int,
    min_green_ns_ms: int,
    min_green_ew_ms: int,
    min_yellow_ms: int,
    min_red_ns_ms: int,
    min_red_ew_ms: int,
    jitter_ms: int,
):
    """
    Produce a 1 Hz NEMA-style timing log with two rings:
      - Ring1 phases: 2 then 4
      - Ring2 phases: 6 then 8
    Sequence per cycle (NORMAL mode):
      NS (2/6) Green -> Yellow -> All-Red -> EW (4/8) Green -> Yellow -> All-Red -> repeat

    'elapsed_ms' resets to 0 on each state change, then grows ~1000ms/second with slight jitter.
    'min_red_*_ms' enforces an additional minimum red time for that approach before it can go green again.
    At accident_utc + flash_delay_s, mode becomes FLASH_Y/R for flash_duration_s, then returns to NORMAL.
    """
    # CSV header
    header = [
        "timestamp","intersection_id","mode",
        "ring1_phase","ring1_state","ring1_elapsed_ms",
        "ring2_phase","ring2_state","ring2_elapsed_ms",
        "p1","p2","p3","p4","p5","p6","p7","p8",
        "event"
    ]

    # States
    MODE_NORMAL = "NORMAL"
    MODE_FLASH = "FLASH_Y/R"

    # Per-second jitter generator (bounded, deterministic-ish based on timestamp)
    def jitter(dt: datetime) -> int:
        if jitter_ms <= 0: return 0
        # simple hash-like pseudo randomness from seconds
        n = int(dt.timestamp())
        j = ((1103515245 * (n ^ 0x5bd1e995) + 12345) & 0x7fffffff) % (2*jitter_ms+1)
        return j - jitter_ms  # in [-jitter_ms, +jitter_ms]

    # Phase mapping helpers for outputs
    def phase_heads(r1_phase, r1_state, r2_phase, r2_state, mode):
        # Default all red
        p = {"p1":"R","p2":"R","p3":"R","p4":"R","p5":"R","p6":"R","p7":"R","p8":"R"}
        if mode == MODE_FLASH:
            # Major street N/S (phases 2 & 6) flashing yellow; minor E/W (4 & 8) flashing red
            p.update({"p2":"FY","p6":"FY","p4":"FR","p8":"FR"})
            return p
        # Normal mode: set heads by active phases per ring
        # When ring1_phase==2 and ring1_state==G -> p2=G, etc.
        if r1_phase in (2,4):
            key = f"p{r1_phase}"
            p[key] = r1_state if r1_state in ("G","Y") else "R"
        if r2_phase in (6,8):
            key = f"p{r2_phase}"
            p[key] = r2_state if r2_state in ("G","Y") else "R"
        return p

    # Timing control
    tick = timedelta(seconds=1)
    end_utc = start_utc + timedelta(hours=hours)
    flash_start = (accident_utc + timedelta(seconds=flash_delay_s))
    flash_end = flash_start + timedelta(seconds=flash_duration_s)

    # State machine for NORMAL ops
    # Start with NS green (2/6), then swap to EW green (4/8)
    current_mode = MODE_NORMAL
    r1_phase, r2_phase = 2, 6
    r1_state, r2_state = "G", "G"
    r1_elapsed, r2_elapsed = 0, 0  # ms
    last_ns_green_end = None
    last_ew_green_end = None

    # Keep track of when each approach last entered red to honor min_red
    ns_red_since = start_utc  # NS phases 2/6 are red when EW side is green/yellow/AR
    ew_red_since = None       # EW red starts after NS turns green initially

    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)

        t = start_utc
        while t <= end_utc:
            # Mode transitions for flash window
            if current_mode != MODE_FLASH and t >= flash_start and t < flash_end:
                # Enter FLASH mode
                current_mode = MODE_FLASH
                # Write the transition row with event
                p = phase_heads(r1_phase, r1_state, r2_phase, r2_state, current_mode)
                w.writerow([
                    fmt_ts(t), intersection_id, current_mode,
                    "", "", "", "", "", "",
                    p["p1"],p["p2"],p["p3"],p["p4"],p["p5"],p["p6"],p["p7"],p["p8"],
                    "MODE_CHANGE:FLASH_MANUAL"
                ])
                # During flash, normal ring/phase fields are blank
                t += tick
                # Keep emitting flash rows until flash_end
                while t < flash_end:
                    p = phase_heads(r1_phase, r1_state, r2_phase, r2_state, current_mode)
                    w.writerow([
                        fmt_ts(t), intersection_id, current_mode,
                        "", "", "", "", "", "",
                        p["p1"],p["p2"],p["p3"],p["p4"],p["p5"],p["p6"],p["p7"],p["p8"],
                        ""
                    ])
                    t += tick
                # Exit flash: revert to NORMAL at flash_end boundary; restart with AR then NS green
                current_mode = MODE_NORMAL
                # Force an all-red clearance (2 seconds) then resume NS green
                r1_phase, r2_phase = 2, 6
                r1_state, r2_state = "AR", "AR"
                r1_elapsed = r2_elapsed = 0
                # Emit the AR rows on/after flash_end until done with 2s
                for i in range(2):
                    p = {"p1":"R","p2":"R","p3":"R","p4":"R","p5":"R","p6":"R","p7":"R","p8":"R"}
                    w.writerow([
                        fmt_ts(t), intersection_id, current_mode,
                        r1_phase, r1_state, r1_elapsed,
                        r2_phase, r2_state, r2_elapsed,
                        p["p1"],p["p2"],p["p3"],p["p4"],p["p5"],p["p6"],p["p7"],p["p8"],
                        ""
                    ])
                    t += tick
                    r1_elapsed += 1000 + jitter(t)
                    r2_elapsed += 1000 + jitter(t)
                # Then switch to NS green start
                r1_state, r2_state = "G", "G"
                r1_elapsed = r2_elapsed = 0
                ns_red_since = t  # NS becomes not red anymore now; but track EW red starting
                ew_red_since = t
                # Continue loop
                continue

            if current_mode == MODE_FLASH:
                # (All handled in block above)
                t += tick
                continue

            # NORMAL mode logic
            # Determine required minima for current state
            if r1_state == "G" and r2_state == "G":
                # Green state on NS or EW depending on phases
                if (r1_phase, r2_phase) == (2,6):
                    min_green_ms = min_green_ns_ms
                else:
                    min_green_ms = min_green_ew_ms

                if r1_elapsed >= min_green_ms and r2_elapsed >= min_green_ms:
                    # After min green, advance to Y
                    r1_state = r2_state = "Y"
                    r1_elapsed = r2_elapsed = 0

            elif r1_state == "Y" and r2_state == "Y":
                if r1_elapsed >= min_yellow_ms and r2_elapsed >= min_yellow_ms:
                    r1_state = r2_state = "AR"
                    r1_elapsed = r2_elapsed = 0

            elif r1_state == "AR" and r2_state == "AR":
                # Determine which approach will get green next
                if (r1_phase, r2_phase) == (2,6):
                    # Completed NS side; enforce EW min_red before allowing EW green
                    if ew_red_since is None:
                        ew_ok = True
                    else:
                        ew_ok = (t - ew_red_since) >= timedelta(milliseconds=min_red_ew_ms)
                    if ew_ok:
                        r1_phase, r2_phase = 4, 8
                        r1_state = r2_state = "G"
                        r1_elapsed = r2_elapsed = 0
                        # NS turns red now
                        ns_red_since = t
                        ew_red_since = None
                else:
                    # Completed EW side; enforce NS min_red before allowing NS green
                    if ns_red_since is None:
                        ns_ok = True
                    else:
                        ns_ok = (t - ns_red_since) >= timedelta(milliseconds=min_red_ns_ms)
                    if ns_ok:
                        r1_phase, r2_phase = 2, 6
                        r1_state = r2_state = "G"
                        r1_elapsed = r2_elapsed = 0
                        # EW turns red now
                        ew_red_since = t
                        ns_red_since = None

            # Emit row
            p = phase_heads(r1_phase, r1_state, r2_phase, r2_state, current_mode)
            w.writerow([
                fmt_ts(t), intersection_id, current_mode,
                r1_phase if current_mode==MODE_NORMAL else "",
                r1_state if current_mode==MODE_NORMAL else "",
                clamp(r1_elapsed, 0, 10_000_000),
                r2_phase if current_mode==MODE_NORMAL else "",
                r2_state if current_mode==MODE_NORMAL else "",
                clamp(r2_elapsed, 0, 10_000_000),
                p["p1"],p["p2"],p["p3"],p["p4"],p["p5"],p["p6"],p["p7"],p["p8"],
                ""  # event (only set on flash entry)
            ])

            # Advance time
            t += tick
            # Update elapsed with jitter
            j = jitter(t)
            r1_elapsed = max(0, r1_elapsed + 1000 + j)
            r2_elapsed = max(0, r2_elapsed + 1000 + j)

    return out_path

def main():
    ap = argparse.ArgumentParser(description="Generate NEMA-style timing logs with flash window.")
    ap.add_argument("--out", default="timing.csv")
    ap.add_argument("--intersection-id", type=int, default=17)
    ap.add_argument("--start", default="2025-08-12T12:00:00Z", help="UTC start time, e.g. 2025-08-12T12:00:00Z")
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--accident", default="2025-08-12T14:37:25Z", help="UTC time of incident trigger, e.g. 2025-08-12T14:37:25Z")
    ap.add_argument("--flash-delay-s", type=int, default=270, help="Seconds after accident to start flash (manual switch)")
    ap.add_argument("--flash-duration-s", type=int, default=600, help="Seconds to remain in flash mode")
    ap.add_argument("--min-green-ns-ms", type=int, default=20000)
    ap.add_argument("--min-green-ew-ms", type=int, default=20000)
    ap.add_argument("--min-yellow-ms", type=int, default=3000)
    ap.add_argument("--min-red-ns-ms", type=int, default=10000)
    ap.add_argument("--min-red-ew-ms", type=int, default=10000)
    ap.add_argument("--jitter-ms", type=int, default=50, help="Max jitter added/subtracted to elapsed_ms per second")
    args = ap.parse_args()

    start = parse_iso_z(args.start)
    accident = parse_iso_z(args.accident)

    generate(
        out_path=args.out,
        intersection_id=args.intersection_id,
        start_utc=start,
        hours=args.hours,
        accident_utc=accident,
        flash_delay_s=args.flash_delay_s,
        flash_duration_s=args.flash_duration_s,
        min_green_ns_ms=args.min_green_ns_ms,
        min_green_ew_ms=args.min_green_ew_ms,
        min_yellow_ms=args.min_yellow_ms,
        min_red_ns_ms=args.min_red_ns_ms,
        min_red_ew_ms=args.min_red_ew_ms,
        jitter_ms=args.jitter_ms,
    )

if __name__ == "__main__":
    main()
