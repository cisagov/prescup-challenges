import os, pathlib, secrets

_STORE = pathlib.Path("/tmp/admin_session.txt")

def get_admin_session() -> str:
    """Provide a stable admin_session for this container lifetime.

    Priority:
      1) ADMIN_SESSION env var (fixed for grading/replays)
      2) Value persisted in /tmp/admin_session.txt
      3) Fresh random token persisted on first use
    """
    v = os.getenv("ADMIN_SESSION")
    if v:
        return v.strip()
    if _STORE.exists():
        return _STORE.read_text().strip()
    v = secrets.token_urlsafe(16)  
    _STORE.write_text(v)
    return v

