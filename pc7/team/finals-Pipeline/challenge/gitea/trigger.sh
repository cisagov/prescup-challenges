#!/bin/bash
# Create runner trigger token
resp=$(curl -fsS -X POST \
  -H "PRIVATE-TOKEN: $ROOT_PAT" \
  --data "description=beacon" \
  "http://localhost:80/api/v4/projects/3/triggers")

trigger_token=$(echo $resp | cut -d ',' -f 2 | cut -d ':' -f 2 | cut -d '"' -f 2)

# Every 10 seconds, trigger a pipeline using the token
while true; do
    curl --request POST "http://localhost:80/api/v4/projects/3/trigger/pipeline?token=$trigger_token&ref=main"
    sleep 45
done