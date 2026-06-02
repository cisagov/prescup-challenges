# payload_base.py — Allowed payload class for the deserialization challenge
import hmac as _hmac
import hashlib as _hashlib


class ChallengePayload:
    """Container for deserialization challenge payloads.

    Attributes required by the server verifier:
        marker  — must equal 'nech'
        nonce   — must be an integer
        run     — callable; the server invokes obj.run(secret)
    """

    def __init__(self, marker=None, nonce=None):
        self.marker = marker
        self.nonce = nonce

    def run(self, secret):
        """Compute HMAC-SHA256(secret, str(nonce)) and return verification dict.

        The server compares provided_raw.encode()[:6] against the first 6 raw
        HMAC bytes.  Because .encode() defaults to UTF-8, bytes >= 0x80 expand
        to two bytes and break alignment.  Choose a nonce whose HMAC prefix is
        all-ASCII (each byte < 0x80) for the comparison to succeed.
        """
        h = _hmac.new(secret.encode(), str(self.nonce).encode(), _hashlib.sha256)
        mac_raw = h.digest()[:6]
        return {"unlock": True, "mac": mac_raw.decode("latin-1")}