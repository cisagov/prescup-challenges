#!/bin/bash
set -euo pipefail

export USER_UID=1000
export USER_GID=1000

DATA_DIR="/data"
GITEA_DIR="${DATA_DIR}/gitea"
CONF_DIR="${GITEA_DIR}/conf"

mkdir -p "${CONF_DIR}" \
         "${GITEA_DIR}/data" \
         "${GITEA_DIR}/log" \
         "${GITEA_DIR}/repositories"

chown -R "${USER_UID}:${USER_GID}" "${GITEA_DIR}"
chmod 755 "${GITEA_DIR}" "${CONF_DIR}" || true

APP_INI="${CONF_DIR}/app.ini"

if [[ ! -f "${APP_INI}" ]]; then
  echo "[gitea] writing app.ini"

  ROOT_URL="${GITEA_ROOT_URL:-http://gitea:8080/}"
  SSH_DOMAIN="${GITEA_SSH_DOMAIN:-gitea}"
  SSH_PORT="${GITEA_SSH_PORT:-22}"

  tmpfile="$(mktemp)"
  sed \
    -e "s|ROOT_URL           = http://gitea/|ROOT_URL           = ${ROOT_URL}|g" \
    -e "s|SSH_DOMAIN         = gitea|SSH_DOMAIN         = ${SSH_DOMAIN}|g" \
    -e "s|SSH_PORT           = 22|SSH_PORT           = ${SSH_PORT}|g" \
    /app.ini.template > "${tmpfile}"

  install -o "${USER_UID}" -g "${USER_GID}" -m 640 "${tmpfile}" "${APP_INI}"
  rm -f "${tmpfile}"
else
  chown "${USER_UID}:${USER_GID}" "${APP_INI}" || true
fi

echo "[gitea] starting gitea web"
su-exec "${USER_UID}:${USER_GID}" gitea web -c "${APP_INI}" &
GITEA_PID=$!

echo "[gitea] waiting for http://127.0.0.1:8080/"
until curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1; do
  if ! kill -0 "${GITEA_PID}" >/dev/null 2>&1; then
    echo "[gitea] gitea exited early; dumping last logs (if any)..." >&2
    tail -n 200 "${GITEA_DIR}/log/gitea.log" 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

echo "[gitea] bootstrapping users/repos/workflows"
set +e
bash -x /bootstrap.sh 2>&1 | tee /tmp/bootstrap.log
BOOT_RC=${PIPESTATUS[0]}
set -e

if [[ "${BOOT_RC}" -ne 0 ]]; then
  echo "[gitea] bootstrap failed with rc=${BOOT_RC}; see /tmp/bootstrap.log"
  tail -f /dev/null
fi

wait "${GITEA_PID}"
