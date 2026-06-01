#!/bin/bash
set -euo pipefail

APP_INI="/data/gitea/conf/app.ini"
DB_PATH="/data/gitea/gitea.db"

GITEA_HTTP="http://127.0.0.1:8080"
GITEA_HTTP_DOCKERNET="http://127.0.0.1:8080"

ADMIN_USER="${ADMIN_USER:?}"
ADMIN_PASS="${ADMIN_PASS:?}"
ADMIN_EMAIL="${ADMIN_EMAIL:?}"

TEST_USER="${TEST_USER:?}"
TEST_PASS="${TEST_PASS:?}"
TEST_EMAIL="${TEST_EMAIL:?}"

DEV_USER="${DEV_USER:?}"
DEV_PASS="${DEV_PASS:?}"
DEV_EMAIL="${DEV_EMAIL:?}"

TOKEN2="${TOKEN2:?}"

USER_UID="${USER_UID:-1000}"
USER_GID="${USER_GID:-1000}"

log() { echo "[bootstrap] $*" >&2; }
die() { echo "[bootstrap] ERROR: $*" >&2; exit 1; }

gitea_cli() {
  su-exec "${USER_UID}:${USER_GID}" gitea "$@"
}

# ---- wait for API (HTTP) ----
wait_for_api() {
  log "waiting for API..."
  until curl -fsS "${GITEA_HTTP}/api/v1/version" >/dev/null 2>&1; do
    sleep 1
  done
  log "API is up"
}

# ---- wait for CLI/DB readiness ----
wait_for_cli_db() {
  log "waiting for gitea CLI/database readiness..."
  until gitea_cli admin user list -c "${APP_INI}" >/dev/null 2>&1; do
    sleep 1
  done
  log "gitea CLI is ready"
}

# ---- sqlite helpers ----
require_sqlite() {
  command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 not found in image"
  [[ -f "${DB_PATH}" ]] || die "db not found at ${DB_PATH} (check [database] PATH in app.ini)"
}

has_col() {
  local col="$1"
  require_sqlite
  sqlite3 "${DB_PATH}" "SELECT 1 FROM pragma_table_info('user') WHERE name='${col}' LIMIT 1;" | grep -qx "1"
}

dump_user_table_cols() {
  require_sqlite
  log "sqlite user table columns:"
  sqlite3 -noheader "${DB_PATH}" "SELECT name FROM pragma_table_info('user') ORDER BY cid;" \
    | sed 's/^/ - /' >&2
}

wait_for_user_table_schema() {
  local timeout="${1:-60}"
  local interval="${2:-2}"
  local elapsed=0

  log "waiting for sqlite user table schema readiness..."

  while (( elapsed < timeout )); do
    require_sqlite

    local cols
    cols="$(sqlite3 -noheader "${DB_PATH}" "SELECT name FROM pragma_table_info('user') ORDER BY cid;" 2>/dev/null || true)"

    if echo "${cols}" | grep -Eq '^(is_admin|is_active|prohibit_login|is_restricted|restricted)$'; then
      log "sqlite user table schema is ready"
      return 0
    fi

    log "schema not ready yet; retrying in ${interval}s"
    sleep "${interval}"
    elapsed=$((elapsed + interval))
  done

  dump_user_table_cols
  die "sqlite user table schema did not become ready within ${timeout}s"
}

force_user_admin_sqlite() {  # admin user only
  local lower="$1"
  require_sqlite

  local sets=()
  has_col "is_admin"       && sets+=("is_admin=1")
  has_col "is_active"      && sets+=("is_active=1")
  has_col "prohibit_login" && sets+=("prohibit_login=0")
  has_col "is_restricted"  && sets+=("is_restricted=0")
  has_col "restricted"     && sets+=("restricted=0")

  if [[ "${#sets[@]}" -eq 0 ]]; then
    dump_user_table_cols
    die "no expected columns found in sqlite user table (schema changed?)"
  fi

  sqlite3 "${DB_PATH}" "UPDATE 'user' SET $(IFS=,; echo "${sets[*]}") WHERE lower_name='${lower}';"
}

force_user_active_sqlite() { # normal users
  local lower="$1"
  require_sqlite

  local sets=()
  has_col "is_active"      && sets+=("is_active=1")
  has_col "prohibit_login" && sets+=("prohibit_login=0")
  has_col "is_restricted"  && sets+=("is_restricted=0")
  has_col "restricted"     && sets+=("restricted=0")

  if [[ "${#sets[@]}" -eq 0 ]]; then
    dump_user_table_cols
    die "no expected columns found in sqlite user table (schema changed?)"
  fi

  sqlite3 "${DB_PATH}" "UPDATE 'user' SET $(IFS=,; echo "${sets[*]}") WHERE lower_name='${lower}';"
}

# robust match without assuming column positions
user_exists_cli() {
  local u="$1"
  gitea_cli admin user list -c "${APP_INI}" \
    | tr -s ' ' \
    | grep -Eiq "(^|[[:space:]])${u}([[:space:]]|$)"
}

ensure_user_cli() {
  local u="$1" p="$2" e="$3" is_admin="${4:-false}"

  if user_exists_cli "${u}"; then
    log "user exists: ${u}"
    return 0
  fi

  log "creating user: ${u}"

  local admin_flag=()
  [[ "${is_admin}" == "true" ]] && admin_flag=(--admin)

  gitea_cli admin user create \
    -c "${APP_INI}" \
    --username "${u}" \
    --password "${p}" \
    --email "${e}" \
    "${admin_flag[@]}" \
    --must-change-password=false
}

# ---- api helpers ----
curl_with_code() { curl -sS "$@" -w "\n%{http_code}"; }
api_token_json() {
  local token="$1"; shift
  curl_with_code -H "Authorization: token ${token}" -H "Content-Type: application/json" "$@"
}
api_token() {
  local token="$1"; shift
  curl_with_code \
    -H "Authorization: token ${token}" \
    -H "Content-Type: application/json" \
    "$@"
}

create_user_token() {
  local username="$1"
  local token_name="$2"

  local out tok code
  out="$(
    gitea_cli admin user generate-access-token \
      -c "${APP_INI}" \
      --username "${username}" \
      --token-name "${token_name}" 2>&1
  )"

  tok="$(
    echo "${out}" \
    | tr -d '\r' \
    | grep -Eo '[A-Fa-f0-9]{40}|[A-Za-z0-9_]{20,}' \
    | tail -n 1
  )"

  [[ -n "${tok}" ]] || { echo "${out}" >&2; die "failed to extract token for ${username}"; }

  # Validate token works
  code="$(
    curl -sS -o /dev/null -w "%{http_code}" \
      -H "Authorization: token ${tok}" \
      "${GITEA_HTTP}/api/v1/user"
  )"

  [[ "${code}" == "200" ]] || {
    echo "${out}" >&2
    die "token validation failed for ${username}: HTTP ${code}"
  }

  echo "${tok}"
}

ensure_repo_clean() {
  local repo="$1"

  local resp code body
  resp="$(api_token "${ADMIN_TOKEN}" "${GITEA_HTTP}/api/v1/repos/${ADMIN_USER}/${repo}")"
  code="$(echo "$resp" | tail -n1)"

  if [[ "${code}" == "200" ]]; then
    log "repo exists: ${ADMIN_USER}/${repo} (deleting)"
    resp="$(api_token "${ADMIN_TOKEN}" -X DELETE "${GITEA_HTTP}/api/v1/repos/${ADMIN_USER}/${repo}")"
    code="$(echo "$resp" | tail -n1)"
    if [[ "${code}" != "204" && "${code}" != "200" ]]; then
      body="$(echo "$resp" | sed '$d')"
      echo "$body" >&2
      die "failed to delete repo ${repo}: HTTP ${code}"
    fi
    sleep 1
  fi

  log "creating repo: ${ADMIN_USER}/${repo}"
  resp="$(api_token_json "${ADMIN_TOKEN}" -X POST "${GITEA_HTTP}/api/v1/user/repos" \
    -d "{\"name\":\"${repo}\",\"private\":true,\"auto_init\":false,\"default_branch\":\"main\"}")"
  code="$(echo "$resp" | tail -n1)"
  if [[ "${code}" != "201" && "${code}" != "200" ]]; then
    body="$(echo "$resp" | sed '$d')"
    echo "$body" >&2
    die "failed to create repo ${repo}: HTTP ${code}"
  fi
}

put_secret() {
  local repo="$1" name="$2" value="$3"
  log "setting secret ${name} on ${repo}"
  local resp code body
  resp="$(api_token_json "${ADMIN_TOKEN}" -X PUT "${GITEA_HTTP}/api/v1/repos/${ADMIN_USER}/${repo}/actions/secrets/${name}" \
    -d "{\"data\":\"${value}\"}")"
  code="$(echo "$resp" | tail -n1)"
  if [[ "${code}" != "201" && "${code}" != "204" && "${code}" != "200" ]]; then
    body="$(echo "$resp" | sed '$d')"
    echo "$body" >&2
    die "failed setting secret ${name} on ${repo}: HTTP ${code}"
  fi
}

seed_repo() {
  local repo="$1"
  local src="/seed/${repo}"
  local tmp="/tmp/seed-${repo}"

  [[ -d "${src}" ]] || die "seed directory missing: ${src}"

  log "seeding repo ${repo} from ${src}"

  rm -rf "${tmp}"
  cp -a "${src}" "${tmp}"
  pushd "${tmp}" >/dev/null

  git init -q
  git config user.email "${ADMIN_EMAIL}"
  git config user.name  "${ADMIN_USER}"
  git add -A
  git commit -qm "${repo} commit"
  git branch -M main

  git remote add origin "${GITEA_HTTP_DOCKERNET}/${ADMIN_USER}/${repo}.git"
  git push -q "http://${ADMIN_USER}:${ADMIN_PASS}@127.0.0.1:8080/${ADMIN_USER}/${repo}.git" main --force

  popd >/dev/null
}

set_collab() {
  local repo="$1" user="$2" perm="$3"
  log "setting collaborator ${user} on ${repo} => ${perm}"
  resp="$(api_token_json "${ADMIN_TOKEN}" -X PUT \
    "${GITEA_HTTP}/api/v1/repos/${ADMIN_USER}/${repo}/collaborators/${user}" \
    -d "{\"permission\":\"${perm}\"}")"
  code="$(echo "$resp" | tail -n1)"
  [[ "$code" == "204" || "$code" == "201" || "$code" == "200" ]] || die "failed collaborator set (${repo}->${user}): HTTP ${code}"
}

# ---- main ----
wait_for_api
wait_for_cli_db
wait_for_user_table_schema 60 2

# Ensure users exist (admin first)
ensure_user_cli "${ADMIN_USER}" "${ADMIN_PASS}" "${ADMIN_EMAIL}" "true"

# IMPORTANT: verify admin really exists before continuing
if ! user_exists_cli "${ADMIN_USER}"; then
  log "admin user list output:"
  gitea_cli admin user list -c "${APP_INI}" >&2 || true
  die "admin user '${ADMIN_USER}' still not visible after create"
fi

ensure_user_cli "${TEST_USER}" "${TEST_PASS}" "${TEST_EMAIL}" "false"
ensure_user_cli "${DEV_USER}"  "${DEV_PASS}"  "${DEV_EMAIL}"  "false"

# Force flags
log "forcing ${ADMIN_USER} admin+active (sqlite)"
force_user_admin_sqlite "${ADMIN_USER}"

log "forcing ${TEST_USER} active/loginable (sqlite)"
force_user_active_sqlite "${TEST_USER}"

log "forcing ${DEV_USER} active/loginable (sqlite)"
force_user_active_sqlite "${DEV_USER}"

# Token + runner token
ADMIN_TOKEN="$(create_user_token "${ADMIN_USER}" "bootstrap-admin-$(date +%s)")"
log "admin token acquired and validated"

DEV_TOKEN="$(create_user_token "${DEV_USER}" "dev-pat-$(date +%s)")"
log "dev token acquired and validated"

log "fetching global runner registration token"
resp="$(api_token "${ADMIN_TOKEN}" "${GITEA_HTTP}/api/v1/admin/runners/registration-token")"
body="$(echo "$resp" | sed '$d')"
code="$(echo "$resp" | tail -n1)"
if [[ "${code}" != "201" && "${code}" != "200" ]]; then
  echo "$body" >&2
  die "runner registration token failed: HTTP ${code}"
fi

RUNNER_REG_TOKEN="$(echo "$body" | jq -r '.token // empty')"
[[ -n "${RUNNER_REG_TOKEN}" ]] || die "runner token missing in response"
echo "${RUNNER_REG_TOKEN}" > /tmp/runner_registration_token.txt
log "runner token written to /tmp/runner_registration_token.txt"

# Repos
ensure_repo_clean "dev"
ensure_repo_clean "test"
ensure_repo_clean "infra"

# Collaborators
log "setting collaborators"
set_collab "test"  "${TEST_USER}" "write"  # Developer
set_collab "dev"   "${TEST_USER}" "read"   # Reporter
set_collab "dev"   "${DEV_USER}"  "write"
set_collab "infra" "${DEV_USER}"  "read"

# Protect test main branch
curl -sS -H "Authorization: token $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "http://127.0.0.1:8080/api/v1/repos/root/test/branch_protections" \
  -d '{
    "rule_name": "protect-main",
    "branch_name": "main",
    "enable_push": true,
    "enable_push_whitelist": true,
    "push_whitelist_usernames": ["root", "dev-user"]
  }'


# Secrets
put_secret "dev"   "TOKEN2" "${TOKEN2}"
put_secret "dev"   "DEV_USER" "${DEV_USER}"
put_secret "dev"   "DEV_PASS" "${DEV_PASS}"
put_secret "dev"   "DEV_PAT" "${DEV_TOKEN}"
put_secret "infra" "DEV_PAT" "${DEV_TOKEN}"

# Seed
seed_repo "dev"
seed_repo "test"
seed_repo "infra"

log "done"
