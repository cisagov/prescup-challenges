#!/usr/bin/env bash
set -euo pipefail

# Default file location (change if you want)
file="${1:-/opt/current_challenge.txt}"

if [[ -r "$file" ]]; then
  # Show only the first line; strip CR; avoid empty output
  line="$(head -n 1 "$file" | tr -d '\r')"
  [[ -n "$line" ]] && printf '  %s  \n' "$line" || printf '  %s  \n' "    "
else
  printf '  %s  \n' "    "
fi