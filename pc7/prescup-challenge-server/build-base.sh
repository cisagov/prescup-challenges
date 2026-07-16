#!/usr/bin/env bash
# Build the local challenge-server base image.
#
# A few pc7 challenges use a customized challenge server (grading, hosted files,
# startup scripts) whose grading/Dockerfile builds `FROM pccc/challenge-server:base`.
# That tag isn't on a public registry — build it locally once with this script,
# then `docker compose up --build` those challenges normally.
#
# Challenges that need it: round1-off_the_hook, finals-ghost-stories,
# round1-BACDoor_Access.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker build -t pccc/challenge-server:base "$DIR/challenge-server"
echo "Built image: pccc/challenge-server:base"
