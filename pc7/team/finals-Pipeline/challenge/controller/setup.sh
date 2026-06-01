#!/bin/bash
set -euo pipefail

GITEA_INSTANCE_URL="http://gitea:8080"     # e.g. http://gitea:8080

# Use basic auth
GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-root}"
GITEA_ADMIN_PASS="2214ee7c0356b287bbe4c6ba3401241f"  

# Repo scope (this is what makes it infra-only)
GITEA_ADMIN_USER="${GITEA_ADMIN_USER:-root}"
GITEA_REPO="${GITEA_REPO:-infra}"

RUNNER_NAME="${RUNNER_NAME:-infra-runner}"
RUNNER_LABELS="${RUNNER_LABELS:-infra:host}"

ACT_RUNNER_BIN="${ACT_RUNNER_BIN:-/usr/local/bin/act_runner}"

CONFIG_PATH="${CONFIG_PATH:-/home/runner/config.yaml}"

log() { echo "[controller] $*"; }
die() { echo "[controller] ERROR: $*" >&2; exit 1; }

log "waiting for ${GITEA_INSTANCE_URL}"
until curl -fsS "${GITEA_INSTANCE_URL}/api/v1/version" >/dev/null 2>&1; do
  sleep 1
done
log "gitea is up"

# Locate act_runner
if [[ ! -x "${ACT_RUNNER_BIN}" ]]; then
  for p in ./act_runner /act_runner /usr/local/bin/act_runner /usr/bin/act_runner; do
    if [[ -x "$p" ]]; then
      ACT_RUNNER_BIN="$p"
      break
    fi
  done
fi
[[ -x "${ACT_RUNNER_BIN}" ]] || die "act_runner binary missing; set ACT_RUNNER_BIN or fix Dockerfile"

# Fetch runner registration token via BASIC AUTH (GET)
fetch_repo_reg_token() {
  resp="$(curl -sS --user "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASS}" \
    -X GET \
    -H "Content-Type: application/json" \
    -w "\n%{http_code}" \
    "http://gitea:8080//api/v1/repos/${GITEA_ADMIN_USER}/${GITEA_REPO}/actions/runners/registration-token")"

    code="$(echo "$resp" | tail -n1)"
    body="$(echo "$resp" | sed '$d')"

    token="$(echo "$body" | jq -r '.token // empty' 2>/dev/null || true)"
      [[ -n "${token}" ]] || return 1
      echo "${token}"
      return 0
}

log "fetching REPO runner registration token for ${GITEA_ADMIN_USER}/${GITEA_REPO}"
REG_TOKEN=""
until REG_TOKEN="$(fetch_repo_reg_token)"; do
  log "retrying repo token fetch in 2s..."
  sleep 2
done
log "repo runner registration token acquired"

# Register once per container lifetime
# IMPORTANT: act_runner stores registration in .runner (default). If your container is ephemeral,
# it will register each boot (fine).
if [[ -f "/home/runner/.runner" ]]; then
  log "runner already registered (.runner exists); skipping register"
else
  log "registering REPO-SCOPED runner name=${RUNNER_NAME} labels=${RUNNER_LABELS}"
  "${ACT_RUNNER_BIN}" register --no-interactive \
    --instance "${GITEA_INSTANCE_URL}" \
    --token "${REG_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --labels "${RUNNER_LABELS}"
fi

# log "starting daemon"
# exec "${ACT_RUNNER_BIN}" --config "${CONFIG_PATH}" daemon
