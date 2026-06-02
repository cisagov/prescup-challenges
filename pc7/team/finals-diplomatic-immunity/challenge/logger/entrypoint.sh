#!/usr/bin/env bash
set -euo pipefail


# logger-node/entrypoint.sh
# Production-friendly entrypoint. Generates a Brainpool cert whose serial encodes TOKEN1.


: "${TOKEN1?Environment variable TOKEN1 must be provided (printable ASCII)}"
: "${TOKEN1_PKI_SCHEME:=brainpoolP256r1}"
: "${LOG_NOISE:=high}"


APP_DIR=/app
CERT_DIR=${APP_DIR}/certs
DATA_DIR=${APP_DIR}/data
UVICORN_CMD="uvicorn app.main:app --host 0.0.0.0 --port 8080 --proxy-headers"


mkdir -p "${CERT_DIR}" "${DATA_DIR}"


# Create deterministic serial from TOKEN1: big-endian integer of ASCII bytes
SER_DEC=$(python3 - <<'PY'
import os
t = os.environ['TOKEN1'].encode('ascii')
print(int.from_bytes(t, 'big'))
PY
)


# Choose curve
if [ "${TOKEN1_PKI_SCHEME}" = "brainpool" ] || [ "${TOKEN1_PKI_SCHEME}" = "brainpoolP256r1" ]; then
CURVE="brainpoolP256r1"
else
CURVE="prime256v1"
fi


# Generate EC private key
openssl genpkey -algorithm EC \
-pkeyopt ec_paramgen_curve:${CURVE} \
-pkeyopt ec_param_enc:named_curve \
-out "${CERT_DIR}/event.key" 2>/dev/null


# Create CSR (subject minimal)
openssl req -new -key "${CERT_DIR}/event.key" \
-subj "/CN=embassy-logger/O=Embassy" \
-out "${CERT_DIR}/event.csr" 2>/dev/null


# Self-sign with explicit serial (decimal computed above), output DER
openssl x509 -req -in "${CERT_DIR}/event.csr" -signkey "${CERT_DIR}/event.key" \
-days 365 -set_serial "${SER_DEC}" -outform DER -out "${CERT_DIR}/event.der"


# Normalize naming for API exposure
cp "${CERT_DIR}/event.der" "${CERT_DIR}/event_certificate.der"

# Generate PEM copy for logging
if [ ! -f "${CERT_DIR}/event.pem" ]; then
  openssl x509 -in "${CERT_DIR}/event.der" -inform DER -out "${CERT_DIR}/event.pem" 2>/dev/null || true
fi

# Emit a structured log file that also embeds the PEM certificate
mkdir -p "${DATA_DIR}"
LOG_FILE="${DATA_DIR}/logs.txt"
{
  ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  echo "${ts} logger.embassy.svc INFO Diplomatic clearance certificate generated serial=${SER_DEC}"
  echo "${ts} logger.embassy.svc INFO Event certificate written to /artifacts/event_certificate.der"
  echo
  if [ -f "${CERT_DIR}/event.pem" ]; then
    cat "${CERT_DIR}/event.pem"
  fi
} > "${LOG_FILE}"

exec ${UVICORN_CMD}