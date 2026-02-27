#!/usr/bin/env bash
# BlueFlex-Switch-331 updater
# Validates the update package, acquires a lock, backs up the current version,
# and writes the new version to the configured version file.

set -Eeuo pipefail

###############################################################################
## Globals & Defaults
###############################################################################
SCRIPT_NAME=${0##*/}
CONFIG=${CONFIG:-/etc/blueflex/traffic.conf}
LOG_FILE=${LOG_FILE:-/var/log/blueflex/update.log}
FORCE=false
NEW_VERSION=""

###############################################################################
## Logging Helpers
###############################################################################
log() {
  local level="$1"; shift
  local msg="$*"
  printf "%s [%s] %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$level" "$msg" | tee -a "$LOG_FILE"
  logger -t blueflex-update "[$level] $msg" || true
}
die() { log "ERROR" "$*"; exit 1; }

###############################################################################
## INI Parsing (key=value only)
###############################################################################
ini_get() {
  # usage: ini_get <section> <key> <file>
  local section="$1" key="$2" file="$3"
  awk -F'=' -v s="[$section]" -v k="$key" '
    $0 ~ "^\s*#"{next}
    tolower($0) ~ "^\s*\["{ in_section = (tolower($0)==tolower(s)) }
    in_section && tolower($1) ~ "^\s*"tolower(k)"\s*$" {
      gsub(/^\s+|\s+$/, "", $2); print $2; exit
    }
  ' "$file"
}

###############################################################################
## Argument Parsing
###############################################################################
usage() {
  cat <<USAGE
$SCRIPT_NAME - BlueFlex-Switch-331 updater
Usage: $SCRIPT_NAME [--config PATH] --version X.Y.Z [--force] [--log-file PATH]

  --config PATH     Path to traffic.conf (default: $CONFIG)
  --version SEMVER  Version string to write to version_file (required)
  --force           Allow model mismatches
  --log-file PATH   Write logs to this file
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) CONFIG="$2"; shift 2;;
      --version) NEW_VERSION="$2"; shift 2;;
      --force) FORCE=true; shift;;
      --log-file) LOG_FILE="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) die "Unknown argument: $1";;
    esac
  done
  [[ -n "$NEW_VERSION" ]] || die "Missing required --version"
}

###############################################################################
## Preconditions & Helpers
###############################################################################
require_root() { [[ $EUID -eq 0 ]] || die "Must run as root"; }

check_model() {
  local want="BlueFlex-Switch-331"
  local have
  have="$(ini_get device model "$CONFIG" || true)"
  [[ -n "$have" ]] || die "Could not read [device].model from $CONFIG"
  if [[ "$have" != "$want" && "$FORCE" != "true" ]]; then
    die "Model '$have' does not match required '$want' (use --force to override)"
  fi
  log INFO "Model check: $have"
}

get_conf() {
  local section="$1" key="$2"
  ini_get "$section" "$key" "$CONFIG"
}

get_version_file() {
  local vf
  vf="$(get_conf device version_file)"
  [[ -n "$vf" ]] || die "version_file not set in $CONFIG"
  printf "%s" "$vf"
}

acquire_lock() {
  local lock
  lock="$(get_conf update lock_file)"
  [[ -n "$lock" ]] || lock="/run/blueflex-update.lock"
  if [[ -e "$lock" ]]; then
    die "Another update appears to be running (lock: $lock)"
  fi
  mkdir -p "$(dirname "$lock")"
  touch "$lock"
  trap 'rm -f "$lock"' EXIT
}

ensure_dirs() {
  local vf="$1"
  mkdir -p "$(dirname "$vf")"
  mkdir -p "$(get_conf update backup_dir)"
  mkdir -p "$(dirname "$LOG_FILE")"
}

backup_version() {
  local vf="$1"
  local bkdir ts dst cur
  bkdir="$(get_conf update backup_dir)"
  ts="$(date -u +'%Y%m%dT%H%M%SZ')"
  dst="$bkdir/version.$ts.bak"
  cur=""
  [[ -f "$vf" ]] && cur="$(cat "$vf" || true)"
  printf "%s\n" "$cur" > "$dst"
  log INFO "Backup written: $dst"
}

verify_hashes() {
  local staging hash_file algo
  staging="$(get_conf update staging_dir)"
  hash_file="$(get_conf update hash_file)"
  algo="$(get_conf update hash_algo)"
  [[ -n "$staging" && -n "$hash_file" && -n "$algo" ]] || die "Update config missing (staging/hash_file/hash_algo)"
  local list="$staging/$hash_file"
  [[ -f "$list" ]] || die "Hash list not found: $list"
  case "$algo" in
    sha256) cmd="sha256sum -c";;
    sha1)   cmd="sha1sum -c";;
    md5)    cmd="md5sum -c";;
    *) die "Unsupported hash_algo: $algo";;
  esac
  (cd "$staging" && $cmd "$hash_file")
  log INFO "Hashes verified with $algo"
}

verify_signature() {
  local req pk staging sig
  req="$(get_conf update require_signature)"
  [[ "${req,,}" == "true" ]] || { log INFO "Signature verification disabled"; return; }
  pk="$(get_conf update public_key)"
  staging="$(get_conf update staging_dir)"
  sig="$staging/package.tgz.sig"
  [[ -f "$pk" && -f "$sig" && -f "$staging/package.tgz" ]] || die "Signature inputs missing"
  openssl dgst -sha256 -verify "$pk" -signature "$sig" "$staging/package.tgz"
  log INFO "Signature verified"
}

run_hooks() {
  local staging
  staging="$(get_conf update staging_dir)"
  if [[ -x "$staging/preinstall.sh" ]]; then
    log INFO "Running preinstall hook"
    "$staging/preinstall.sh"
  fi
  if [[ -x "$staging/postinstall.sh" ]]; then
    log INFO "Running postinstall hook"
    "$staging/postinstall.sh"
  fi
}

write_version() {
  local vf="$1"
  printf "%s\n" "$NEW_VERSION" > "$vf"
  chmod 0644 "$vf"
  sync
  log INFO "Wrote version: $NEW_VERSION -> $vf"
}

###############################################################################
## Main
###############################################################################
main() {
  parse_args "$@"
  require_root
  [[ -f "$CONFIG" ]] || die "Config not found: $CONFIG"
  log INFO "Using config: $CONFIG"
  check_model
  acquire_lock
  local vf
  vf="$(get_version_file)"
  ensure_dirs "$vf"
  verify_hashes
  verify_signature
  run_hooks
  backup_version "$vf"
  write_version "$vf"
  log INFO "Update completed"
}

main "$@"
