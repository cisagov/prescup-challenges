#!/bin/bash
set -euo pipefail

# --- Runtime token ingestion (no baked artifacts) ---
TOKEN_PATH="${TOKEN_PATH:-/var/lib/usb/native}"
mkdir -p "$TOKEN_PATH"
chmod 700 "$TOKEN_PATH"
chown root:root "$TOKEN_PATH"

# Capture SESSIONID early (used later in memo); then remove from env to avoid exposure
SESSIONID="${SESSION_ID:-}"
SALT="${SESSIONID}"

if [[ -z "$SALT" ]]; then
  echo "[setup] ERROR: SESSION_ID is required for token derivation" >&2
  exit 1
fi

derive_and_store () {
  local name="$1" value="${2:-}"
  if [[ -n "$value" ]]; then
    python3 - "$TOKEN_PATH" "$name" "$SALT" "$value" << 'PY'
import hashlib, os, sys
out_dir, name, salt, token = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
# Derivation: SHA256(salt + ":" + token). Store hex digest only.
d = hashlib.sha256((salt + ":" + token).encode("utf-8")).hexdigest()
path = os.path.join(out_dir, f"{name}.hash")
with open(path, "w", encoding="utf-8") as f:
    f.write(d)
os.chmod(path, 0o600)
PY
    chown root:root "${TOKEN_PATH}/${name}.hash"
    echo "[setup] wrote ${TOKEN_PATH}/${name}.hash"
  fi
}

# Store ONLY derived values (no plaintext token files)
derive_and_store "cam1" "${TOKEN1:-}"
derive_and_store "cam2" "${TOKEN2:-}"
derive_and_store "ghost" "${TOKEN3:-}"
derive_and_store "suitcase" "${TOKEN4:-}"

# Defensive cleanup: remove any legacy plaintext path if present (shouldn't exist in fresh containers)
rm -rf /etc/prison/tokens 2>/dev/null || true

# Unset sensitive env so sshd/user sessions cannot read them from inherited environment
unset TOKEN1 TOKEN2 TOKEN3 TOKEN4 SESSION_ID TOKEN_PATH 
export TOKEN1="" TOKEN2="" TOKEN3="" TOKEN4="" SESSION_ID="" TOKEN_PATH=""
echo "[setup] cleared all tokens and setup artifacts"

# --- Hard-to-get obfuscated ops memo (runtime only) ---
# Accepts: 37, 0x37, -37, -0x37
RAW_HEX="${OP_HINT_KEY_HEX:-37}"
RAW_HEX="${RAW_HEX#0x}"  # strip optional leading 0x if present

sign=1
if [[ "$RAW_HEX" == -* ]]; then
  sign=-1
  RAW_HEX="${RAW_HEX#-}"
fi

# Validate hex; fallback to 37 if invalid
if [[ ! "$RAW_HEX" =~ ^[0-9A-Fa-f]+$ ]]; then
  echo "[setup] WARN: OP_HINT_KEY_HEX invalid ('$OP_HINT_KEY_HEX'), defaulting to 37" >&2
  RAW_HEX="37"
  sign=1
fi

# Convert to int, then reduce to a single byte for XOR
HINT_KEY=$(( sign * 16#$RAW_HEX ))
KEY_BYTE=$(( HINT_KEY & 0xFF ))

LOG_DIR="/var/log/prison"
ROT_DIR="${LOG_DIR}/rotated"
HIDDEN_DIR="/opt/.prison/.ops"
CACHE_DIR="${LOG_DIR}/.cache"

ENC_PATH="${ROT_DIR}/.ops_memo.txt.gz.enc"
LINK1="${HIDDEN_DIR}/.blk"
LINK2="${CACHE_DIR}/.vidbuf"

mkdir -p "$LOG_DIR" "$ROT_DIR" "$HIDDEN_DIR" "$CACHE_DIR"
chmod 755 "$LOG_DIR" "$ROT_DIR"
chmod 711 "$HIDDEN_DIR" "$CACHE_DIR"

MEMO_CONTENT=$(cat << EOF
PRISON-CAM OPS MEMO
- Gh0st node requires ARMED state before accepting protocol traffic.
- Arming token formula: token = SHA256("GHOST-ARM:" + key_hex)
- Submit via internal channel:
  curl -X POST http://gh0st-protocol:8081/arm -d "code=<hex>"
- Observations:
  * Handshake uses single-byte opcode (acknowledged when correct).
  * Follow-on auth appears fixed-length: 1 + 2 + 4 = 7 bytes.
  * Counter anomaly suggests underflow acceptance.
  * Ghost-sync: tight epoch window (± few seconds).
  * Meeting-room GUI remains LOCKED until ghost-sync completes.
EOF
)

tmpmemo="$(mktemp)"
tmpgz="$(mktemp)"
printf "%s\n" "$MEMO_CONTENT" > "$tmpmemo"
gzip -c "$tmpmemo" > "$tmpgz"
rm -f "$tmpmemo"

# Encrypt gzip with XOR key byte
python3 - << PY "$tmpgz" "$ENC_PATH" "$KEY_BYTE"
import sys
src, dst, key = sys.argv[1], sys.argv[2], int(sys.argv[3]) & 0xFF
data = open(src,'rb').read()
enc = bytes((b ^ key) for b in data)
open(dst,'wb').write(enc)
PY

rm -f "$tmpgz"
chmod 644 "$ENC_PATH"

ln -sf "$ENC_PATH" "$LINK1"
ln -sf "$LINK1" "$LINK2"

echo "$(date -u '+%F %T') :: camera rotate :: framebuf=.cache/.vidbuf :: key=0x$(printf '%02x' "$KEY_BYTE")" >> "${LOG_DIR}/camera_log.txt"
chmod 644 "${LOG_DIR}/camera_log.txt"

# --- Start SSHD (if installed) ---
mkdir -p /var/run/sshd
exec /usr/sbin/sshd -D