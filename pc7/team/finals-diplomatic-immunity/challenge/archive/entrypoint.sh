#!/usr/bin/env sh
set -eu

umask 077

log() {
  printf '%s %s\n' "[archive]" "$*" >&2
}

die() {
  printf '%s %s\n' "[archive][fatal]" "$*" >&2
  exit 1
}

require_file() {
  [ -f "$1" ] || die "missing file: $1"
}

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "missing required binary: $1"
}

cleanup() {
  rc=$?
  if [ -n "${WORKDIR:-}" ] && [ -d "${WORKDIR:-}" ]; then
    rm -rf "$WORKDIR"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# Required challenge values
: "${TOKEN1:?TOKEN1 is required}"
: "${TOKEN2:?TOKEN2 is required}"
: "${TOKEN3:?TOKEN3 is required}"
: "${TOKEN4:?TOKEN4 is required}"

# Optional runtime tuning
: "${ARCHIVE_HOST:=0.0.0.0}"
: "${ARCHIVE_PORT:=8080}"
: "${UVICORN_LOG_LEVEL:=info}"

# Shared CA baked into the image
CA_SRC_CRT="/opt/embassy-pki/embassy-ca.crt"
CA_SRC_KEY="/opt/embassy-pki/embassy-ca.key"

require_bin openssl
require_bin split
require_bin xxd
require_bin tar
require_bin uvicorn

require_file "$CA_SRC_CRT"
require_file "$CA_SRC_KEY"

# Runtime workspace
WORKDIR="$(mktemp -d /tmp/archive.XXXXXX)"
DATA_DIR="$WORKDIR/data"
ART_DIR="$DATA_DIR/artifacts"
EXP_DIR="$DATA_DIR/export"
PKG_DIR="$DATA_DIR/pkg"
CA_DIR="$WORKDIR/ca"

mkdir -p "$ART_DIR" "$EXP_DIR" "$PKG_DIR" "$CA_DIR"

log "initializing archive workspace"

# Copy shared CA into runtime workspace
cp "$CA_SRC_CRT" "$CA_DIR/ca.crt"
cp "$CA_SRC_KEY" "$CA_DIR/ca.key"
chmod 0644 "$CA_DIR/ca.crt"
chmod 0600 "$CA_DIR/ca.key"

# Generate RSA private key for Token4 artifact recovery
log "generating recovery keypair"
openssl genrsa -out "$DATA_DIR/privkey.pem" 2048 >/dev/null 2>&1
openssl rsa -in "$DATA_DIR/privkey.pem" -outform DER -out "$DATA_DIR/privkey.der" >/dev/null 2>&1

# Deterministically split DER key into 3 binary fragments
KEY_SIZE="$(wc -c < "$DATA_DIR/privkey.der" | tr -d ' ')"
[ "$KEY_SIZE" -gt 0 ] || die "generated private key DER is empty"

# Ceiling division for 3 roughly equal chunks
CHUNK_SIZE=$(( (KEY_SIZE + 2) / 3 ))
split -b "$CHUNK_SIZE" "$DATA_DIR/privkey.der" "$EXP_DIR/share_"

mv "$EXP_DIR/share_aa" "$EXP_DIR/shareA.bin"
mv "$EXP_DIR/share_ab" "$EXP_DIR/shareB.bin"
mv "$EXP_DIR/share_ac" "$EXP_DIR/shareC.bin"

# Write Token4 file
printf '%s\n' "$TOKEN4" > "$DATA_DIR/TOKEN4.txt"

# Generate client certificate for Token5 using the shared CA
log "issuing client certificate"
openssl genrsa -out "$DATA_DIR/client.key" 2048 >/dev/null 2>&1
openssl req -new \
  -key "$DATA_DIR/client.key" \
  -out "$DATA_DIR/client.csr" \
  -subj "/CN=Challenger Client" >/dev/null 2>&1

openssl x509 -req \
  -in "$DATA_DIR/client.csr" \
  -CA "$CA_DIR/ca.crt" \
  -CAkey "$CA_DIR/ca.key" \
  -CAcreateserial \
  -out "$DATA_DIR/client.crt" \
  -days 365 >/dev/null 2>&1

chmod 0600 "$DATA_DIR/client.key"
chmod 0644 "$DATA_DIR/client.crt"

# Package classified material
cp "$DATA_DIR/client.key"   "$PKG_DIR/client.key"
cp "$DATA_DIR/client.crt"   "$PKG_DIR/client.crt"
cp "$CA_DIR/ca.crt"         "$PKG_DIR/ca-chain.pem"
cp "$DATA_DIR/TOKEN4.txt"   "$PKG_DIR/TOKEN4.txt"

tar -cf "$DATA_DIR/classified.tar" -C "$PKG_DIR" .

# Generate AES-256 key + IV
KEY_HEX="$(openssl rand -hex 32)"
IV_HEX="$(openssl rand -hex 16)"

[ "${#KEY_HEX}" -eq 64 ] || die "generated AES key hex length invalid"
[ "${#IV_HEX}" -eq 32 ] || die "generated IV hex length invalid"

printf '%s' "$IV_HEX" > "$ART_DIR/classified.iv"

# Encrypt archive with PKCS#7 padding enabled
log "encrypting classified archive"
openssl enc -aes-256-cbc \
  -K "$KEY_HEX" \
  -iv "$IV_HEX" \
  -in "$DATA_DIR/classified.tar" \
  -out "$ART_DIR/classified.tar.enc"

# Convert AES key safely from hex to binary and wrap with RSA OAEP
printf '%s' "$KEY_HEX" | xxd -r -p > "$DATA_DIR/aes.key"

openssl rsa -in "$DATA_DIR/privkey.pem" -pubout -out "$DATA_DIR/pub.pem" >/dev/null 2>&1
openssl pkeyutl -encrypt \
  -pubin \
  -inkey "$DATA_DIR/pub.pem" \
  -in "$DATA_DIR/aes.key" \
  -out "$ART_DIR/sym.key.rsa-oaep" \
  -pkeyopt rsa_padding_mode:oaep

# Expose app data directory to FastAPI app
export DATA_DIR

# Final sanity checks
require_file "$ART_DIR/classified.iv"
require_file "$ART_DIR/classified.tar.enc"
require_file "$ART_DIR/sym.key.rsa-oaep"
require_file "$EXP_DIR/shareA.bin"
require_file "$EXP_DIR/shareB.bin"
require_file "$EXP_DIR/shareC.bin"

SYM_SIZE="$(wc -c < "$ART_DIR/sym.key.rsa-oaep" | tr -d ' ')"
[ "$SYM_SIZE" -eq 256 ] || die "wrapped AES key has unexpected size: $SYM_SIZE"

log "archive service ready on ${ARCHIVE_HOST}:${ARCHIVE_PORT}"

exec uvicorn app.main:app \
  --host "$ARCHIVE_HOST" \
  --port "$ARCHIVE_PORT" \
  --log-level "$UVICORN_LOG_LEVEL"