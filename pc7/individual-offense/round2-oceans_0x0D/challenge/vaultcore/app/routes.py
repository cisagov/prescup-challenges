from __future__ import annotations
import base64, hmac, hashlib, socket, struct, time, os
from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field
from .shift_rhythm import RhythmSettings
from .alert import AlertEngine
from .rate_limit import TokenBucketLimiter
from .state import VaultState
from .token_dispense import TokenDispenser
from .token1 import bucket_id, rhythm_sig
from .token2_fw import FirmwareRelease, build_known_good_bundle, verify_and_install_bundle
from .token4_floor import stego_export_blob
from .deps import (
    get_settings, get_vault, get_alert,
    get_limiter_sync, get_limiter_fw, get_limiter_t3, get_limiter_t4,
    get_dispenser
)

router = APIRouter()

class SyncReq(BaseModel):
    sync: str = Field(min_length=16, max_length=16, pattern=r"^[0-9a-f]{16}$")
    bucket: int | None = None

class ReplaySubmitReq(BaseModel):
    frame_b64: str = Field(min_length=8, max_length=20000)

class GhostRedeemReq(BaseModel):
    proof_b64: str = Field(min_length=16, max_length=256)

class FloorEnterReq(BaseModel):
    code: str = Field(min_length=8, max_length=32, pattern=r"^[A-Z2-9]+$")

@router.get("/healthz")
async def healthz():
    return {"ok": True}

@router.get("/api/state")
async def api_state(vault: VaultState = Depends(get_vault), alert: AlertEngine = Depends(get_alert)):
    snap = await alert.snapshot()
    assert vault.tokens is not None
    return {
        "ts": int(time.time()),
        "alert": {
            "score": round(snap.score, 2),
            "level": snap.level,
            "state": snap.state,
            "lockdown_until": snap.lockdown_until_ts,
        },
        "tokens": {
            "token1": {"found": vault.tokens.token1_found, "found_at": vault.tokens.token1_found_at},
            "token2": {"found": vault.tokens.token2_found, "found_at": vault.tokens.token2_found_at},
            "token3": {"found": vault.tokens.token3_found, "found_at": vault.tokens.token3_found_at},
            "token4": {"found": vault.tokens.token4_found, "found_at": vault.tokens.token4_found_at},
        },
    }

# ---------------------------------------------------------------------------
# TOKEN 1: Rhythm Sync
# ---------------------------------------------------------------------------


@router.post("/api/ops/sync")
async def ops_sync(
    req: SyncReq,
    request: Request,
    vault: VaultState = Depends(get_vault),
    dispenser: TokenDispenser = Depends(get_dispenser),
    alert: AlertEngine = Depends(get_alert),
    limiter: TokenBucketLimiter = Depends(get_limiter_sync),
    settings = Depends(get_settings),
):
    ip = request.client.host if request.client else "unknown"
    if not await limiter.allow(f"sync:{ip}"):
        await alert.penalize(settings.alert_penalty_rate_limit, "SYNC_RATE_LIMIT")
        raise HTTPException(status_code=429, detail="too many requests")
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")

    assert vault.secrets is not None
    # Use the running roulette rhythm engine
    rhythm = getattr(request.app.state, "rhythm", None)
    if rhythm is None:
        raise HTTPException(status_code=503, detail="rhythm engine offline")

    bucket_seconds = int(rhythm.s.bucket_seconds)
    slop = int(settings.t1_accept_bucket_slop)

    if req.bucket is not None:
        b_base = int(req.bucket)
    else:
        now = time.time()
        b_base = int(now // bucket_seconds)

    candidates: list[str] = []
    for delta in range(-slop, slop + 1):
        b = b_base + delta
        candidates.append(
            rhythm.expected_code_for_bucket(b).strip().lower()
        )

    if req.sync.strip().lower() not in candidates:
        await alert.penalize(settings.alert_penalty_bad_sync, "BAD_SYNC")
        raise HTTPException(status_code=403, detail="access denied")

    await vault.mark_token_found(1)

    dispenser.issue(
        token_id=1,
        context="house_rhythm",
        metadata={
            "bucket": b_base,
            "ip": ip,
        },
    )


    await vault.mark_token_found(1)

    dispenser.issue(
        token_id=1,
        context="house_rhythm",
        metadata={
            "bucket": b_base,
            "ip": ip,
        },
    )

    return {"ok": True, "msg": "rhythm synchronized", "next": "request receipt"}


@router.get("/api/ops/receipt/latest")
async def ops_receipt_latest(
    dispenser: TokenDispenser = Depends(get_dispenser),
):
    receipt = dispenser.latest()
    if not receipt:
        raise HTTPException(status_code=404, detail="no receipt available")
    return receipt

# ---------------------------------------------------------------------------
# TOKEN 2: Firmware parser mismatch
# ---------------------------------------------------------------------------
async def _t2_effective_release_id(vault: VaultState, settings) -> str:
    # If admin pins a release id, use it
    rid = (settings.t2_release_id or "").strip()
    if rid:
        return rid

    # Otherwise use a stable, db-cached generated ID
    cached = await vault.db.get("t2_release_id")
    if cached:
        return cached

    assert vault.secrets is not None
    # "random-ish" but stable: derived from master secret + version
    suffix = hashlib.sha256(
        b"T2|RID|" + vault.secrets.master_secret + settings.t2_release_version.encode("utf-8")
    ).hexdigest()[:6]

    rid = f"fw-runtime-{settings.t2_release_version}-{suffix}"
    await vault.db.set("t2_release_id", rid)
    return rid

@router.get("/api/fw/catalog")
async def fw_catalog(vault: VaultState = Depends(get_vault), settings = Depends(get_settings)):
    rid = await _t2_effective_release_id(vault, settings)
    return {"releases": [{"id": rid, "version": settings.t2_release_version, "notes": "Operational stability update"}]}

@router.get("/api/fw/download/{release_id}")
async def fw_download(release_id: str, vault: VaultState = Depends(get_vault), settings = Depends(get_settings)):
    assert vault.secrets is not None
    expected = await _t2_effective_release_id(vault, settings)
    if release_id != expected:
        raise HTTPException(status_code=404, detail="unknown release")
    rel = FirmwareRelease(release_id=release_id, version=settings.t2_release_version, notes="Operational stability update")
    bundle = build_known_good_bundle(vault.secrets.master_secret, rel)
    return Response(
        content=bundle,
        media_type="application/x-tar",
        headers={"Content-Disposition": f'attachment; filename="vault-fw-{release_id}.tar"'},
    )

@router.post("/api/fw/upload")
async def fw_upload(
    request: Request,
    file: UploadFile = File(...),
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    limiter_fw: TokenBucketLimiter = Depends(get_limiter_fw),
    settings = Depends(get_settings),
):
    ip = request.client.host if request.client else "unknown"
    if not await limiter_fw.allow(f"fw:{ip}"):    
        await alert.penalize(settings.t2_alert_penalty_fw_spam, "FW_RATE_LIMIT")
        raise HTTPException(status_code=429, detail="too many requests")
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")

    snap = await alert.snapshot()
    if snap.level > settings.t2_require_alert_max:
        await alert.penalize(settings.t2_alert_penalty_fw_spam, "FW_BLOCKED_HOT")
        raise HTTPException(status_code=403, detail="firmware interface locked by SOC")

    data = await file.read()
    if len(data) > settings.t2_max_upload_bytes:
        await alert.penalize(settings.t2_alert_penalty_fw_spam, "FW_TOO_LARGE")
        raise HTTPException(status_code=413, detail="bundle too large")

    assert vault.secrets is not None
    try:
        ok, mode, _installer_view = verify_and_install_bundle(vault.secrets.master_secret, data)
    except Exception:
        await alert.penalize(settings.t2_alert_penalty_bad_fw, "FW_PARSE_ERROR")
        raise HTTPException(status_code=400, detail="malformed firmware bundle")

    if not ok:
        await alert.penalize(settings.t2_alert_penalty_bad_fw, "FW_BAD_SIG")
        raise HTTPException(status_code=403, detail="signature invalid")

    if mode == "blueprint":
        try:
            await vault.mark_token_found(2)
        except Exception:
            # Don't brick the whole service if persistence is temporarily unhappy
            log.exception("t2_mark_found_failed")
        return {"ok": True, "msg": "firmware accepted", "mode": "blueprint"}

    return {"ok": True, "msg": "firmware accepted", "mode": "normal"}

@router.get("/api/ops/maintenance/blueprint-slip")
async def blueprint_slip(
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    dispenser: TokenDispenser = Depends(get_dispenser),
    settings = Depends(get_settings),
):
    assert vault.tokens is not None
    snap = await alert.snapshot()

    if not vault.tokens.token2_found:
        raise HTTPException(status_code=404, detail="no slips")
    if settings.token_reveal_mode not in ("receipt", "both"):
        raise HTTPException(status_code=404, detail="maintenance printer offline")
    if snap.level > settings.token_reveal_requires_alert_max:
        raise HTTPException(status_code=403, detail="slip intercepted by SOC")

    return {"terminal": "ENG-AUDIT-12", "ts": int(time.time()), "auth": dispenser.token2(), "note": "blueprint access granted"}

# ---------------------------------------------------------------------------
# TOKEN 3: Ghost in the Stack (replayd exploit -> ghost proof redemption)
# ---------------------------------------------------------------------------

@router.get("/api/ops/ghost/challenge")
async def ghost_challenge(
    request: Request,
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    settings = Depends(get_settings),
):
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")
    snap = await alert.snapshot()
    if snap.level > settings.t3_require_alert_max:
        raise HTTPException(status_code=403, detail="ghost console sealed by SOC")

    # Nonce is stored server-side with TTL; redemption is one-shot.
    nonce = hashlib.sha256(b"T3|NONCE|" + os.urandom(16) + struct.pack("<I", int(time.time()))).digest()[:16]
    nonce_b64 = base64.b64encode(nonce).decode()
    expires = int(time.time()) + settings.t3_proof_ttl_seconds
    vault.t3_challenges[nonce_b64] = expires

    return {"nonce_b64": nonce_b64, "expires_ts": expires, "ttl_seconds": settings.t3_proof_ttl_seconds}

def _talk_replayd(port: int, frame: bytes) -> bytes:
    if len(frame) > 8192:
        raise ValueError("frame too large")
    msg = struct.pack("<I", len(frame)) + frame
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.2)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(msg)
        return s.recv(65535)
    finally:
        try: s.close()
        except Exception: pass

@router.post("/api/ops/replay/submit")
async def replay_submit(
    req: ReplaySubmitReq,
    request: Request,
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    limiter_t3: TokenBucketLimiter = Depends(get_limiter_t3),
    settings = Depends(get_settings),
):
    ip = request.client.host if request.client else "unknown"
    if not await limiter_t3.allow(f"replay:{ip}"):    
        await alert.penalize(settings.t3_alert_penalty_spam, "T3_RATE_LIMIT")
        raise HTTPException(status_code=429, detail="too many requests")
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")

    snap = await alert.snapshot()
    if snap.level > settings.t3_require_alert_max:
        await alert.penalize(settings.t3_alert_penalty_spam, "T3_BLOCKED_HOT")
        raise HTTPException(status_code=403, detail="replay console locked")

    try:
        frame = base64.b64decode(req.frame_b64, validate=False)
    except Exception:
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_BAD_B64")
        raise HTTPException(status_code=400, detail="bad base64")

    if len(frame) > settings.t3_max_frame_bytes:
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_TOO_BIG")
        raise HTTPException(status_code=413, detail="frame too large")

    try:
        raw = _talk_replayd(settings.t3_replay_port, frame)
    except Exception:
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_REPLAYD_ERR")
        raise HTTPException(status_code=502, detail="replay engine unavailable")

    # Return raw response base64 so teams can script it cleanly.
    return {"ok": raw.startswith(b"OK "), "resp_b64": base64.b64encode(raw).decode()}

@router.post("/api/ops/ghost/redeem")
async def ghost_redeem(
    req: GhostRedeemReq,
    request: Request,
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    settings = Depends(get_settings),
):
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")

    snap = await alert.snapshot()
    if snap.level > settings.t3_require_alert_max:
        raise HTTPException(status_code=403, detail="ghost channel sealed")

    try:
        proof = base64.b64decode(req.proof_b64, validate=False)
    except Exception:
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_BAD_PROOF_B64")
        raise HTTPException(status_code=400, detail="bad proof")

    if len(proof) != 16 + 32:
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_BAD_PROOF_LEN")
        raise HTTPException(status_code=400, detail="bad proof length")

    nonce = proof[:16]
    tag = proof[16:]
    nonce_b64 = base64.b64encode(nonce).decode()

    exp = vault.t3_challenges.get(nonce_b64, 0)
    if exp <= int(time.time()):
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_EXPIRED_NONCE")
        raise HTTPException(status_code=403, detail="nonce expired")

    assert vault.t3_ghost_secret is not None
    expected = hmac.new(vault.t3_ghost_secret, b"T3|" + nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        await alert.penalize(settings.t3_alert_penalty_bad_frame, "T3_BAD_TAG")
        raise HTTPException(status_code=403, detail="invalid proof")

    # One-shot consume
    vault.t3_challenges.pop(nonce_b64, None)
    await vault.mark_token_found(3)
    return {"ok": True, "msg": "ghost mode engaged"}

@router.get("/api/ops/maintenance/ghost-slip")
async def ghost_slip(
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    dispenser: TokenDispenser = Depends(get_dispenser),
    settings = Depends(get_settings),
):
    assert vault.tokens is not None
    snap = await alert.snapshot()
    if not vault.tokens.token3_found:
        raise HTTPException(status_code=404, detail="no slips")
    if snap.level > settings.token_reveal_requires_alert_max:
        raise HTTPException(status_code=403, detail="slip intercepted by SOC")
    return {"terminal":"SOC-TRACE-03","ts":int(time.time()),"auth":dispenser.token3(),"note":"ghost proof accepted"}

# ---------------------------------------------------------------------------
# TOKEN 4: False Floor (encrypted surveillance export -> stego floor code -> redeem)
# ---------------------------------------------------------------------------

@router.get("/api/ops/surveillance/export")
async def surveillance_export(
    request: Request,
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    limiter_t4: TokenBucketLimiter = Depends(get_limiter_t4),
    settings = Depends(get_settings),
):
    ip = request.client.host if request.client else "unknown"
    if not await limiter_t4.allow(f"export:{ip}"):    
        await alert.penalize(settings.t4_alert_penalty_export_spam, "T4_RATE_LIMIT")
        raise HTTPException(status_code=429, detail="too many requests")
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")

    snap = await alert.snapshot()
    if snap.level > settings.t4_requires_alert_max:
        await alert.penalize(settings.t4_alert_penalty_export_spam, "T4_BLOCKED_HOT")
        raise HTTPException(status_code=403, detail="export blocked by SOC")

    assert vault.tokens is not None
    if settings.t4_require_token3 and not vault.tokens.token3_found:
        raise HTTPException(status_code=403, detail="ghost mode required")

    assert vault.t3_ghost_secret is not None
    assert vault.t4_floor_code is not None
    blob = stego_export_blob(
        ghost_secret=vault.t3_ghost_secret,
        floor_code=vault.t4_floor_code,
        lsb_bits=settings.t4_stego_lsb_bits,
        cipher_block=settings.t4_cipher_block,
    )
    if blob["bytes"] > settings.t4_max_export_bytes:
        await alert.penalize(settings.t4_alert_penalty_bad_export, "T4_TOO_BIG")
        raise HTTPException(status_code=500, detail="export sizing fault")

    return blob

@router.post("/api/ops/floor/enter")
async def floor_enter(
    req: FloorEnterReq,
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    settings = Depends(get_settings),
):
    if await alert.is_locked_down():
        raise HTTPException(status_code=423, detail="casino lockdown in effect")
    snap = await alert.snapshot()
    if snap.level > settings.t4_requires_alert_max:
        raise HTTPException(status_code=403, detail="access denied by SOC")

    assert vault.t4_floor_code is not None
    if req.code != vault.t4_floor_code:
        await alert.penalize(settings.t4_alert_penalty_bad_export, "T4_BAD_CODE")
        raise HTTPException(status_code=403, detail="wrong code")

    await vault.mark_token_found(4)
    return {"ok": True, "msg": "floor latch released"}

@router.get("/api/ops/maintenance/floor-slip")
async def floor_slip(
    vault: VaultState = Depends(get_vault),
    alert: AlertEngine = Depends(get_alert),
    dispenser: TokenDispenser = Depends(get_dispenser),
    settings = Depends(get_settings),
):
    assert vault.tokens is not None
    snap = await alert.snapshot()
    if not vault.tokens.token4_found:
        raise HTTPException(status_code=404, detail="no slips")
    if snap.level > settings.token_reveal_requires_alert_max:
        raise HTTPException(status_code=403, detail="slip intercepted by SOC")
    return {"terminal":"SUBFLOOR-01","ts":int(time.time()),"auth":dispenser.token4(),"note":"false floor entered"}
