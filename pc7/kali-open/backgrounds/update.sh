#!/bin/bash

BGDIR="/usr/share/backgrounds/kali-16x9/pccc/"
DEFAULT_FALLBACK="$BGDIR/1.png"
TARGET_SYMLINK="/usr/share/backgrounds/kali-16x9/default"

SELECTED=""

#############################
# 1. Explicit background
#############################
if [[ -n "$PCCC_BACKGROUND" ]]; then
    CANDIDATE="$BGDIR/$PCCC_BACKGROUND"
    if [[ -f "$CANDIDATE" ]]; then
        SELECTED="$CANDIDATE"
        echo "Using explicit background: $SELECTED"
    else
        echo "WARNING: PCCC_BACKGROUND not found: $CANDIDATE"
        if [[ -f "$DEFAULT_FALLBACK" ]]; then
            SELECTED="$DEFAULT_FALLBACK"
            echo "Falling back to: $SELECTED"
        else
            echo "WARNING: Fallback 1.png not found. Leaving existing wallpaper unchanged."
            exit 0
        fi
    fi
fi

#############################
# 2. Event backgrounds
#############################
if [[ -z "$SELECTED" && -n "$PCCC_EVENT" ]]; then
    mapfile -t MATCHES < <(find "$BGDIR" -maxdepth 1 -type f -name "${PCCC_EVENT}-*.png" | sort)

    if (( ${#MATCHES[@]} > 0 )); then
        SELECTED="${MATCHES[RANDOM % ${#MATCHES[@]}]}"
        echo "Using event background: $SELECTED"
    else
        echo "WARNING: No backgrounds for event '$PCCC_EVENT'. Falling back to numeric set."
    fi
fi

#############################
# 3. Default numeric selection
#############################
if [[ -z "$SELECTED" ]]; then
    mapfile -t NUMS < <(find "$BGDIR" -maxdepth 1 -type f -regex '.*/[0-9]+\.png' | sort)

    if (( ${#NUMS[@]} > 0 )); then
        SELECTED="${NUMS[RANDOM % ${#NUMS[@]}]}"
        echo "Using default numeric background: $SELECTED"
    else
        echo "WARNING: No numeric backgrounds found. Leaving existing wallpaper unchanged."
        exit 0
    fi
fi

#############################
# 4. Update symlink
#############################
if [[ -n "$SELECTED" ]]; then
    ln -sfn "$SELECTED" "$TARGET_SYMLINK"
    echo "Wallpaper symlink updated → $SELECTED"
else
    echo "No valid background selected. Leaving existing symlink unchanged."
fi
