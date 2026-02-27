from __future__ import annotations
from fastapi import Request, HTTPException
from .config import Settings
from .state import VaultState
from .alert import AlertEngine
from .rate_limit import TokenBucketLimiter
from .token_dispense import TokenDispenser

def get_settings(request: Request) -> Settings:
    return request.app.state.settings

def get_vault(request: Request) -> VaultState:
    return request.app.state.vault

def get_alert(request: Request) -> AlertEngine:
    return request.app.state.alert

def get_limiter_sync(request: Request) -> TokenBucketLimiter:
    return request.app.state.limiter_sync

def get_limiter_fw(request: Request) -> TokenBucketLimiter:
    return request.app.state.limiter_fw

def get_limiter_t3(request: Request) -> TokenBucketLimiter:
    return request.app.state.limiter_t3

def get_limiter_t4(request: Request) -> TokenBucketLimiter:
    return request.app.state.limiter_t4

def get_dispenser(request: Request) -> TokenDispenser:
    dispenser = getattr(request.app.state, "dispenser", None)
    if dispenser is None:
        raise HTTPException(
            status_code=503,
            detail="Token dispenser not initialized",
        )
    return dispenser

