#!/usr/bin/env sh

set -e

[ -z "${GAME_TOKEN}" ] && {
    echo "ERROR: GAME_TOKEN environment variable is not set."
    exit 1
}

[ -z "${DEBUG_TOKEN}" ] && {
    echo "ERROR: DEBUG_TOKEN environment variable is not set."
    exit 1
}

# Prepare the anti-cheat script
echo "Replacing addons token with ${GAME_TOKEN}..."
sed -i "s/__TOKEN__/${GAME_TOKEN}/g" /app/resources/ac_node.gd

# # Patch the game
/gdsdecomp/gdre_tools.x86_64 \
    --headless \
    --pck-patch="/app/game/index.pck" \
    --patch-file=/app/resources/ac_node.gd=res://addons/anti-cheating/ac_node.gd \
    --output=/app/game/index.pck

# # Patch the game
/gdsdecomp/gdre_tools.x86_64 \
    --headless \
    --pck-patch="/app/game/debug/index.pck" \
    --patch-file=/app/resources/ac_node.gd=res://addons/anti-cheating/ac_node.gd \
    --output=/app/game/debug/index.pck


echo "Replacing debug build index token with ${DEBUG_TOKEN}..."
sed -i "s/__TOKEN__/${DEBUG_TOKEN}/g" /app/game/debug/index.html

# Start the server
exec "/app/server"