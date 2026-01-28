#!/bin/bash
set -euo pipefail

: "${TOKEN1:?TOKEN1 must be set}"

TMPDIR=/tmp/disk_root
OUTFILE=/challenge/disk_image.dd

echo "[*] Creating disk image directory structure..."
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"/{docs,logs,cache}

# Decoys
echo "Quarterly report draft" > "$TMPDIR/docs/report.txt"
printf "info: boot ok\nwarn: low entropy\n" > "$TMPDIR/logs/system.log"
head -c 2048 /dev/urandom > "$TMPDIR/cache/blob.bin"

# Real token: binary, not contiguous ASCII (prevents strings)
python3 - <<'PY'
import os, secrets, pathlib
root = pathlib.Path("/tmp/disk_root")
token = os.environ["TOKEN1"].encode("utf-8")

out = bytearray()
for b in token:
    out.append(b)
    out.append(secrets.randbelow(256))  # interleaved noise

(root / "token.dat").write_bytes(out)
PY

echo "[*] Generating ext2 disk image (with token.dat present)..."
genext2fs -d "$TMPDIR" -b 204800 "$OUTFILE"

# Delete it INSIDE the image so it becomes recoverable via fls/icat
echo "[*] Deleting /token.dat inside the ext2 image (forensic recovery path)..."
if ! command -v debugfs >/dev/null 2>&1; then
  echo "[FATAL] debugfs not found. Install e2fsprogs (e.g., apt-get install -y e2fsprogs)." >&2
  exit 1
fi

# -w enables writes; rm removes the directory entry but leaves inode/data recoverable
debugfs -w -R "rm /token.dat" "$OUTFILE" >/dev/null

echo "[*] Disk image ready at $OUTFILE"

