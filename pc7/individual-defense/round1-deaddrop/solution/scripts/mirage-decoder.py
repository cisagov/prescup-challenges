from PIL import Image

END = b"\x00\x00"  # your embed uses two null bytes as terminator

img = Image.open("the_second_mirage.png").convert("RGB")
bits = []

for y in range(img.height):
    for x in range(img.width):
        r, g, b = img.getpixel((x, y))
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

out = bytearray()
for i in range(0, len(bits), 8):
    byte_bits = bits[i:i+8]
    if len(byte_bits) < 8:
        break
    val = 0
    for bit in byte_bits:
        val = (val << 1) | bit
    out.append(val)
    if out[-2:] == END:
        out = out[:-2]
        break

print(out.decode("utf-8", errors="replace"))