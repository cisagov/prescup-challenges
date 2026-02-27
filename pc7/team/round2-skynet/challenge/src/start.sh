#!/bin/bash 

OUT_FILE=/app/uploads/coords.bin
#SEED=$((RANDOM % 1000))
SEED=777

# Deleting any existing output files
rm -f $OUT_FILE

# Generate data and add to uploads folder if it exists
if [ -d "/app/uploads/" ]; then
  node /app/generate.js $OUT_FILE $SEED
  echo "Output log saved to /app/uploads/"
fi

/bin/bash
