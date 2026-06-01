import hashlib

def mac(
    key: bytes,
    trailer_id: str,
    nonce: str,
    session_id: str,
    gate_state: str
) -> bytes:
    """
    Custom vendor MAC (intentionally NOT HMAC).
    Order and inclusion are critical.
    """
    blob = (
        key +
        trailer_id.encode() +
        nonce.encode() +
        session_id.encode() +
        gate_state.encode()
    )
    return hashlib.sha1(blob).digest()

