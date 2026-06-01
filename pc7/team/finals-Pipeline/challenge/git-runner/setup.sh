#!/bin/sh
set -euo pipefail

GITEA_INSTANCE_URL="${GITEA_INSTANCE_URL:?}"     # e.g. http://gitea:8080
GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-root}"
GITEA_ADMIN_PASS="2214ee7c0356b287bbe4c6ba3401241f"

RUNNER_NAME="${RUNNER_NAME:-shared-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-shared:host}"

# # Where act_runner is (override in compose if needed)
# ACT_RUNNER_BIN="${ACT_RUNNER_BIN:-/usr/local/bin/act_runner}"

CONFIG_PATH="${CONFIG_PATH:-/home/runner/config.yaml}"
#CONFIG_TEMPLATE="${CONFIG_TEMPLATE:-/home/runner/config.yaml.template}"

log() { echo "[git-runner] $*"; }
die() { echo "[git-runner] ERROR: $*" >&2; exit 1; }

# Wait for gitea web
log "waiting for ${GITEA_INSTANCE_URL}"
until curl -fsS "${GITEA_INSTANCE_URL}/" >/dev/null 2>&1; do
  sleep 1
done
log "gitea is up"

# Fetch runner registration token via BASIC AUTH (GET)
fetch_reg_token() {
  local resp body code token
  resp="$(curl -sS --user "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}" \
    -w "\n%{http_code}" \
    "${GITEA_INSTANCE_URL}/api/v1/admin/runners/registration-token")"

  code="$(echo "$resp" | tail -n1)"
  body="$(echo "$resp" | sed '$d')"

  if [[ "${code}" != "200" && "${code}" != "201" ]]; then
    # print body so you see errors
    echo "$body" >&2
    return 1
  fi

  token="$(echo "$body" | jq -r '.token // empty' 2>/dev/null || true)"
  [[ -n "${token}" ]] || return 1
  echo "${token}"
}

log "fetching runner registration token using basic auth"
REG_TOKEN=""
until REG_TOKEN="$(fetch_reg_token)"; do
  log "retrying token fetch in 2s..."
  sleep 2
done
log "runner registration token acquired"

# Register once per container lifetime
if [[ -f ".runner" ]]; then
  log "runner already registered (.runner exists); skipping register"
else
  log "registering runner name=${RUNNER_NAME} labels=${RUNNER_LABELS}"
  act_runner register --no-interactive \
    --instance "${GITEA_INSTANCE_URL}" \
    --token "${REG_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --labels "${RUNNER_LABELS}"
fi

# log "starting daemon"
# act_runner --config "${CONFIG_PATH}" daemon &
