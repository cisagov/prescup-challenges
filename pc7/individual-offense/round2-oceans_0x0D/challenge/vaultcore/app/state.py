from __future__ import annotations
import base64, hashlib, hmac, logging, secrets, time
from dataclasses import dataclass
from .db import DB

log = logging.getLogger("vault.state")

@dataclass
class TokenState:
    token1_found: bool
    token1_found_at: int
    token1_revealed_once: bool
    token2_found: bool
    token2_found_at: int
    token3_found: bool
    token3_found_at: int
    token4_found: bool
    token4_found_at: int

@dataclass
class RuntimeSecrets:
    master_secret: bytes
    epoch_seed: bytes

def _derive_from_boot_seed(seed_b64: str) -> tuple[bytes, bytes]:
    raw = base64.b64decode(seed_b64)
    master = hmac.new(raw, b"BOOT|MASTER", hashlib.sha256).digest()
    epoch = hmac.new(raw, b"BOOT|EPOCH", hashlib.sha256).digest()[:16]
    return master, epoch

class VaultState:
    def __init__(self, db: DB, master_secret_b64: str, boot_seed_b64: str):
        self.db = db
        self.master_secret_b64 = master_secret_b64
        self.boot_seed_b64 = boot_seed_b64
        self.secrets: RuntimeSecrets | None = None
        self.tokens: TokenState | None = None

        # Runtime-only secrets (never persisted as plaintext)
        self.t3_ghost_secret: bytes | None = None
        self.t3_salt: bytes | None = None
        self.t4_floor_code: str | None = None
        self.t4_salt: bytes | None = None

        # Token3 challenge cache: nonce_b64 -> expires_ts
        self.t3_challenges: dict[str, int] = {}

    async def load_or_init(self) -> None:
        # Master secret source priority: injected -> boot seed -> db -> generated
        if self.master_secret_b64.strip():
            master = base64.b64decode(self.master_secret_b64)
            log.info("master_secret_source", extra={"source":"injected_b64"})
        elif self.boot_seed_b64.strip():
            master, epoch_seed = _derive_from_boot_seed(self.boot_seed_b64)
            log.info("master_secret_source", extra={"source":"boot_seed_derived"})
        else:
            existing = await self.db.get("master_secret_b64")
            if existing:
                master = base64.b64decode(existing)
                log.info("master_secret_source", extra={"source":"db"})
            else:
                master = secrets.token_bytes(32)
                await self.db.set("master_secret_b64", base64.b64encode(master).decode())
                log.info("master_secret_source", extra={"source":"generated_runtime"})

        # Epoch seed: stable within the process lifetime (db-backed unless boot seed is used)
        if self.boot_seed_b64.strip() and not self.master_secret_b64.strip():
            _, epoch_seed = _derive_from_boot_seed(self.boot_seed_b64)
        else:
            epoch_b64 = await self.db.get("t1_epoch_seed_b64")
            if epoch_b64:
                epoch_seed = base64.b64decode(epoch_b64)
            else:
                epoch_seed = secrets.token_bytes(16)
                await self.db.set("t1_epoch_seed_b64", base64.b64encode(epoch_seed).decode())

        self.secrets = RuntimeSecrets(master_secret=master, epoch_seed=epoch_seed)

        # Token flags
        t1_found = (await self.db.get("t1_found")) == "1"
        t1_found_at = int(await self.db.get("t1_found_at") or "0")
        t1_revealed_once = (await self.db.get("t1_revealed_once")) == "1"

        t2_found = (await self.db.get("t2_found")) == "1"
        t2_found_at = int(await self.db.get("t2_found_at") or "0")

        t3_found = (await self.db.get("t3_found")) == "1"
        t3_found_at = int(await self.db.get("t3_found_at") or "0")

        t4_found = (await self.db.get("t4_found")) == "1"
        t4_found_at = int(await self.db.get("t4_found_at") or "0")

        self.tokens = TokenState(
            token1_found=t1_found,
            token1_found_at=t1_found_at,
            token1_revealed_once=t1_revealed_once,
            token2_found=t2_found,
            token2_found_at=t2_found_at,
            token3_found=t3_found,
            token3_found_at=t3_found_at,
            token4_found=t4_found,
            token4_found_at=t4_found_at,
        )

        # Token3 ghost secret salt (stored only as salt; secret derived each boot from master+salt)
        salt_b64 = await self.db.get("t3_salt_b64")
        if salt_b64:
            self.t3_salt = base64.b64decode(salt_b64)
        else:
            self.t3_salt = secrets.token_bytes(16)
            await self.db.set("t3_salt_b64", base64.b64encode(self.t3_salt).decode())
        self.t3_ghost_secret = hmac.new(master, b"T3|GHOST|" + self.t3_salt, hashlib.sha256).digest()

        # Token4 floor code & salt
        t4_salt_b64 = await self.db.get("t4_salt_b64")
        if t4_salt_b64:
            self.t4_salt = base64.b64decode(t4_salt_b64)
        else:
            self.t4_salt = secrets.token_bytes(16)
            await self.db.set("t4_salt_b64", base64.b64encode(self.t4_salt).decode())

        code = await self.db.get("t4_floor_code")
        if code:
            self.t4_floor_code = code
        else:
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            self.t4_floor_code = "".join(secrets.choice(alphabet) for _ in range(12))
            await self.db.set("t4_floor_code", self.t4_floor_code)

    async def mark_token_found(self, token: int) -> None:
        assert self.tokens is not None
        ts = int(time.time())
        if token == 1:
            if self.tokens.token1_found: return
            self.tokens.token1_found = True; self.tokens.token1_found_at = ts
            await self.db.set("t1_found","1"); await self.db.set("t1_found_at", str(ts))
        elif token == 2:
            if self.tokens.token2_found: return
            self.tokens.token2_found = True; self.tokens.token2_found_at = ts
            await self.db.set("t2_found","1"); await self.db.set("t2_found_at", str(ts))
        elif token == 3:
            if self.tokens.token3_found: return
            self.tokens.token3_found = True; self.tokens.token3_found_at = ts
            await self.db.set("t3_found","1"); await self.db.set("t3_found_at", str(ts))
        elif token == 4:
            if self.tokens.token4_found: return
            self.tokens.token4_found = True; self.tokens.token4_found_at = ts
            await self.db.set("t4_found","1"); await self.db.set("t4_found_at", str(ts))
        else:
            raise ValueError("invalid token")

    async def mark_token1_revealed_once(self) -> None:
        assert self.tokens is not None
        if self.tokens.token1_revealed_once:
            return
        self.tokens.token1_revealed_once = True
        await self.db.set("t1_revealed_once", "1")
