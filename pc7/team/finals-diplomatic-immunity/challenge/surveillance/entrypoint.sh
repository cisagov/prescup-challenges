#!/bin/sh
set -eu

: "${TOKEN2:?need TOKEN2}"

# mkdir -p /app/data/frames /app/data/artifacts

# Create a frame image with OCR-able passphrase

python - << 'PY'
from PIL import Image, ImageDraw, ImageFont

text = "CAM_PASSPHRASE=Artemis-Bridge-27"

# High-contrast background
img = Image.new("RGB", (1280, 720), color=(0, 0, 0))
draw = ImageDraw.Draw(img)

# Use a large clean font
try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 64)
except:
    font = ImageFont.load_default()

# Compute text size (Pillow ≥10 removed textsize())
try:
    # Preferred in newer Pillow
    bbox = font.getbbox(text)
    w, h = bbox[2] - bbox[0], bbox[3] - bbox[1]
except:
    # Fallback for older versions
    w, h = font.getsize(text)

# Center the text
x = (img.width - w) // 2
y = (img.height - h) // 2

# Border around text
pad = 40
draw.rectangle(
    (x - pad, y - pad, x + w + pad, y + h + pad),
    outline=(255, 255, 255),
    width=4,
)

# Draw text
draw.text((x, y), text, font=font, fill=(255, 255, 255))

# Save frame
img.save("/app/data/frames/frame-003.jpg")
PY




# Create TOKEN2 zip
printf "%s" "$TOKEN2" > /app/data/TOKEN2.txt
( cd /app/data && zip -q payload.zip TOKEN2.txt )

ITER=10000
PASS="Artemis-Bridge-27"

# Encrypt with Camellia passphrase
openssl enc -camellia-256-cbc -pbkdf2 -salt -iter "$ITER" -md sha256 \
  -in /app/data/payload.zip \
  -out /app/data/artifacts/payload.cam.enc \
  -pass pass:"$PASS"

# UPDATE due to memory limits - Synthesize a short hallway CCTV clip from the key frame so the route looks realistic
mkdir -p /app/data/cctv
ffmpeg -loglevel error -y \
  -loop 1 \
  -i /app/data/frames/frame-003.jpg \
  -t 2 \
  -vf "scale=640:360" \
  -c:v libx264 \
  -preset ultrafast \
  -tune stillimage \
  -pix_fmt yuv420p \
  -movflags +faststart \
  /app/data/cctv/hallway-1.mp4

# Create a simple listing file that hints at available assets
cat > /app/data/list.txt <<'LIST'
cctv/hallway-1.mp4
frames/frame-003.jpg
artifacts/payload.cam.enc
LIST

exec uvicorn main:app --host 0.0.0.0 --port 8080
