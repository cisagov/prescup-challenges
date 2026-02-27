# ---------- Rings / phases (dynamic) ----------
import datetime
from simulator import PED 

PANEL_LOCKED = True

class dynamicTime():
    def __str__(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%m/%d/%Y, %H:%M:%S")

LAST_RESET = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2, hours=4, minutes=5)

class uptime():
    def __str__(self):
        global LAST_RESET
        diff = datetime.datetime.now(datetime.timezone.utc) - LAST_RESET
        mins = int(abs(diff.total_seconds()) // 60)
        h, m = divmod(mins, 60)
        return f"{h}h {m}m"

def defaultPanel():
    return  {
        # Admin
        "page": "status", # Determines which menu page is currently open; either status, main, login, or config
        "cursor": "p1_min", # In config page, determines which field has the edit cursor underneath it. Otherwise ignored
        
        # Ring 1 (Phases 1–4)
        "p1_state": "R",   "p1_t": "00:12", "p1_min": 7,  "p1_max": 25, "p1_calls": "P",  "p1_det": "—",   "p1_ped": "—",  "p1_notes": "",
        "p2_state": "G",   "p2_t": "00:47", "p2_min": 10, "p2_max": 40, "p2_calls": "P",  "p2_det": "—",   "p2_ped": "—", "p2_notes": "",
        "p3_state": "R",   "p3_t": "00:59", "p3_min": 7,  "p3_max": 25, "p3_calls": "—",  "p3_det": "—",   "p3_ped": "—",  "p3_notes": "",
        "p4_state": "R",   "p4_t": "00:59", "p4_min": 7,  "p4_max": 25, "p4_calls": "—",  "p4_det": "—",   "p4_ped": "—",  "p4_notes": "",

        # Ring 2 (Phases 5–8)
        "p5_state": "R",   "p5_t": "00:19", "p5_min": 7,  "p5_max": 25, "p5_calls": "—",  "p5_det": "—",   "p5_ped": "—",  "p5_notes": "",
        "p6_state": "Y",   "p6_t": "00:03", "p6_min": 10, "p6_max": 40, "p6_calls": "—",  "p6_det": "—",   "p6_ped": "—", "p6_notes": "",
        "p7_state": "R",   "p7_t": "00:59", "p7_min": 7,  "p7_max": 25, "p7_calls": "—",  "p7_det": "—",   "p7_ped": "—",  "p7_notes": "",
        "p8_state": "R",   "p8_t": "00:59", "p8_min": 7,  "p8_max": 25, "p8_calls": "—",  "p8_det": "—",   "p8_ped": "—",  "p8_notes": "",

        # Header / system
        "sys_time": dynamicTime(), "tz": "UTC",
        "intersection": "5th St @ 6th St", "mode": "COORDINATED",
        "ctrl_id": "TC-900", "cabinet_id": "CAB-A01",
        "panel_lock": "LOCKED", "ws_status": "CONNECTED", "ws_clients": 2,
        "comms": "LINK-OK", "door": "CLOSED",

        # Coordination
        "plan_no": 3, "cycle_len": 120, "offset": 38, "ref": "N",
        "split_r1": 56, "split_r2": 64,
        "next_force_off": "14:32:22", "next_pair": "2/6", "cycle_t": "00:47",

        # Ped intervals
        "pd2_state": "DW", "pd2_walk": 7, "pd2_fdw": 20, "pd2_cd": "—", "pd2_calls": 0,
        "pd6_state": "DW","pd6_walk": 7, "pd6_fdw": 20, "pd6_cd": "—", "pd6_calls": 0,


        # Overlaps
        "ovl_a_state": "ON",  "ovl_a_ph": "2+6",
        "ovl_b_state": "OFF", "ovl_b_ph": "3+7",
        "ovl_c_state": "OFF", "ovl_c_ph": "4+8",

        # Detections (summary)
        "det_n": "—", "det_s": "—", "det_e": "—", "det_w": "—",

        # Priority / Preemption
        "tp_status": "NONE", "preempt_status": "NONE", "preempt_active": "NONE",

        # Health
        "fault_count": 0, "fault_list": "—", "temp_c": 41.3, "vdc": 24.1,
        "last_reset": LAST_RESET.strftime("%m/%d/%Y, %H:%M:%S"), "uptime": uptime(),

        # Security
        "pin_attempts": 1, "pin_limit": 5, "lockout_status": "CLEAR", "lockout_etr": "—",

        # Next transitions (advisory)
        "r1_next": "Gap-out/FO to P3", "r1_etr": "14:32:22",
        "r2_next": "Red",              "r2_etr": "14:32:08",
    }
RINGS_PANEL = defaultPanel()