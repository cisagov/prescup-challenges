from __future__ import annotations
import hashlib, logging
from dataclasses import dataclass
import time
import hashlib
import hmac
from typing import Dict, List

log = logging.getLogger("vault.dispense")

@dataclass(frozen=True)
class TokenConfig:
    ctfd_token_1: str
    ctfd_token_2: str
    ctfd_token_3: str
    ctfd_token_4: str

class TokenDispenser:
    def __init__(self, cfg: TokenConfig, stable_secret: bytes):
        self.cfg = cfg
        self.stable_secret = stable_secret
        self._cache: dict[int, str] = {}
        self._receipts: list[dict] = []

    def issue(self, token_id: int, context: str, metadata: dict | None = None) -> dict:
        """
        Issue a receipt for a solved token.
        """
        metadata = metadata or {}

        token_value = {
            1: self.cfg.ctfd_token_1,
            2: self.cfg.ctfd_token_2,
            3: self.cfg.ctfd_token_3,
            4: self.cfg.ctfd_token_4,
        }.get(token_id)

        if not token_value:
            raise ValueError(f"Invalid token_id {token_id}")

        issued_at = int(time.time())

        receipt_body = {
            "token_id": token_id,
            "token": token_value,
            "context": context,
            "issued_at": issued_at,
            "metadata": metadata,
        }

        # Optional: tamper-evident receipt signature
        sig = hmac.new(
            self.stable_secret,
            repr(receipt_body).encode(),
            hashlib.sha256,
        ).hexdigest()

        receipt = {
            **receipt_body,
            "signature": sig,
        }

        self._receipts.append(receipt)
        return receipt

    def latest(self) -> dict | None:
        """
        Return the most recently issued receipt, or None.
        """
        if not self._receipts:
            return None
        return self._receipts[-1]

    def _gen(self, prefix: bytes, idx: int) -> str:
        digest = hashlib.sha256(prefix + self.stable_secret).digest()
        hex6 = digest[:3].hex().upper()
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        tail = "".join(alphabet[b % len(alphabet)] for b in digest[3:7])
        return f"PCCC{{0D-{idx:02d}{hex6}{tail}}}"

    def token1(self) -> str:
        if 1 in self._cache: return self._cache[1]
        inj = self.cfg.ctfd_token_1.strip()
        self._cache[1] = inj if inj else self._gen(b"T1|", 1)
        log.info("token1_source", extra={"source": "ctfd_injected" if inj else "runtime_generated"})
        return self._cache[1]

    def token2(self) -> str:
        if 2 in self._cache: return self._cache[2]
        inj = self.cfg.ctfd_token_2.strip()
        self._cache[2] = inj if inj else self._gen(b"T2|", 2)
        log.info("token2_source", extra={"source": "ctfd_injected" if inj else "runtime_generated"})
        return self._cache[2]

    def token3(self) -> str:
        if 3 in self._cache: return self._cache[3]
        inj = self.cfg.ctfd_token_3.strip()
        self._cache[3] = inj if inj else self._gen(b"T3|", 3)
        log.info("token3_source", extra={"source": "ctfd_injected" if inj else "runtime_generated"})
        return self._cache[3]

    def token4(self) -> str:
        if 4 in self._cache: return self._cache[4]
        inj = self.cfg.ctfd_token_4.strip()
        self._cache[4] = inj if inj else self._gen(b"T4|", 4)
        log.info("token4_source", extra={"source": "ctfd_injected" if inj else "runtime_generated"})
        return self._cache[4]
