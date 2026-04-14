#!/usr/bin/env bash
set -euo pipefail
jq -r '.exec_order[]?' "$TCU_STAGING/manifest.json" | while read -r s; do
  bash "$TCU_STAGING/$s"
done
