import threading, time, logging

log = logging.getLogger("controller.sim")
LOCK = threading.RLock()

# NEMA 8-phase, 2-ring sequencing (pairs run concurrently)
PAIR_SEQUENCE = [(1, 5), (2, 6), (3, 7), (4, 8)]

YELLOW_SEC = 3     # clearance yellow
ALL_RED_SEC = 1    # all-red clearance

def _mmss(s: int) -> str:
    m, s = divmod(max(0, int(s)), 60)
    return f"{m:02d}:{s:02d}"

def _green_for_pair(panel: dict, a: int, b: int) -> int:
    """Pick a green time that respects both phases' mins and maxes."""
    amin, amax = int(panel.get(f"p{a}_min", 7)), int(panel.get(f"p{a}_max", 25))
    bmin, bmax = int(panel.get(f"p{b}_min", 7)), int(panel.get(f"p{b}_max", 25))
    low, hi = max(amin, bmin), min(amax, bmax)
    if hi < low: return max(low, 1)
    need = _ped_required_green(panel, a, b)  # ensure ped WALK+FDW fits (with yellow help)
    return max(min(max(low, need), hi), 1)

def _tick(panel: dict, active: set[int], active_state: str, sec_since_change: dict[int, int], cur_state: dict[int, str]):
    """One-second tick: update state + timer for all 8 phases."""
    for n in range(1, 9):
        desired = active_state if n in active else "R"
        if cur_state.get(n) != desired:
            cur_state[n] = desired
            sec_since_change[n] = 0
        else:
            sec_since_change[n] = sec_since_change.get(n, 0) + 1

    # write back to shared dict atomically-ish
    with LOCK:
        for n in range(1, 9):
            panel[f"p{n}_state"] = cur_state[n]
            panel[f"p{n}_t"] = _mmss(sec_since_change[n])

def _run_loop(panel: dict, stop: threading.Event):
    # initialize current state/timers from panel
    cur_state = {n: str(panel.get(f"p{n}_state", "R")) for n in range(1, 9)}
    sec_since_change = {n: 0 for n in range(1, 9)}
    idx = 0

    log.info("Traffic simulator started")
    while not stop.is_set():
        a, b = PAIR_SEQUENCE[idx]
        green = _green_for_pair(panel, a, b)
        _ped_begin_for_pair(panel, a, b)

        # GREEN stage
        for _ in range(green):
            if stop.wait(1): break
            _tick(panel, {a, b}, "G", sec_since_change, cur_state)
            _ped_tick(panel)
        if stop.is_set(): break

        # YELLOW stage
        for _ in range(YELLOW_SEC):
            if stop.wait(1): break
            _tick(panel, {a, b}, "Y", sec_since_change, cur_state)
            _ped_tick(panel)
        if stop.is_set(): break

        # ALL-RED stage (nobody green)
        for _ in range(ALL_RED_SEC):
            if stop.wait(1): break
            _tick(panel, set(), "R", sec_since_change, cur_state)
            _ped_tick(panel)
        if stop.is_set(): break

        idx = (idx + 1) % len(PAIR_SEQUENCE)

    log.info("Traffic simulator stopped")

# --- Pedestrian context (global to simulator) ---
PED = {"2": {"state": "DW", "cd": 0}, "6": {"state": "DW", "cd": 0}}

def _ped_required_green(panel: dict, a: int, b: int) -> int:
    """Extra green needed so green+yellow covers WALK+FDW for any ped with a call."""
    def need(n: int) -> int:
        if n not in (2, 6): return 0
        calls = int(panel.get(f"pd{n}_calls", 0) or 0)
        if not calls: return 0
        walk = int(panel.get(f"pd{n}_walk", 0) or 0)
        fdw  = int(panel.get(f"pd{n}_fdw", 0) or 0)
        return max(walk, walk + fdw - YELLOW_SEC)  # ensure green+yellow >= walk+fdw
    return max(need(a), need(b))

def _ped_begin_for_pair(panel: dict, a: int, b: int):
    """When a pair starts green, kick off WALK if there’s a pending call (phases 2/6 only)."""
    for n in (a, b):
        if n not in (2, 6): continue
        if int(panel.get(f"pd{n}_calls", 0) or 0) > 0 and PED[str(n)]["state"] == "DW":
            PED[str(n)] = {"state": "WALK", "cd": int(panel.get(f"pd{n}_walk", 0) or 0)}
            panel[f"pd{n}_state"] = "WALK"; panel[f"pd{n}_cd"] = PED[str(n)]["cd"]

def _ped_tick(panel: dict):
    """Advance ped timers 1s and handle WALK→FDW→DW transitions."""
    for n in (2, 6):
        st = PED[str(n)]["state"]; cd = PED[str(n)]["cd"]
        if st in ("WALK", "FDW") and cd > 0:
            PED[str(n)]["cd"] -= 1; cd = PED[str(n)]["cd"]
            panel[f"pd{n}_cd"] = cd
            if cd == 0 and st == "WALK":
                PED[str(n)] = {"state": "FDW", "cd": int(panel.get(f"pd{n}_fdw", 0) or 0)}
                panel[f"pd{n}_state"] = "FDW"; panel[f"pd{n}_cd"] = PED[str(n)]["cd"]
            elif cd == 0 and st == "FDW":
                PED[str(n)] = {"state": "DW", "cd": 0}
                panel[f"pd{n}_state"] = "DW"; panel[f"pd{n}_cd"] = "—"
                panel[f"pd{n}_calls"] = 0  # served
    refresh_phase_call_labels(panel) 

def refresh_phase_call_labels(panel: dict):
    for n in range(1, 9):
        veh = bool(panel.get(f"p{n}_det")) and str(panel.get(f"p{n}_det")) != "—"
        ped = int(panel.get(f"pd{n}_calls", 0) or 0) > 0  # 0 for phases w/o peds
        panel[f"p{n}_calls"] = "V,P" if (veh and ped) else "V" if veh else "P" if ped else "—"

def start_traffic_simulator(panel: dict):
    """
    Start the background simulator that mutates RINGS_PANEL in place.
    Returns a stop() function you can call on shutdown.
    """
    stop = threading.Event()
    th = threading.Thread(target=_run_loop, args=(panel, stop), daemon=True)
    th.start()

    def _stop():
        stop.set()
        th.join(timeout=5)
    return _stop
