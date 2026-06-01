import numpy as np
import soundfile as sf
from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES

def sine_wave(freq, length_s, sr=44100, amplitude=0.5):
    t = np.linspace(0, length_s, int(sr*length_s), endpoint=False)
    return amplitude * np.sin(2*np.pi*freq*t)

def save_wav(filename, samples, sr=44100):
    samples = np.asarray(samples)
    maxv = np.max(np.abs(samples)) if samples.size else 1.0
    if maxv > 0:
        samples = samples / maxv * 0.9
    sf.write(filename, samples, sr, subtype='PCM_16')

def embed_lsb_wav(base_wav_samples, message_bytes):
    ints = np.int16(base_wav_samples * 32767)
    bits = np.unpackbits(np.frombuffer(message_bytes, dtype=np.uint8))
    if bits.size > ints.size:
        raise ValueError("message too large for LSB embedding")
    flat = ints.flatten()
    flat[:bits.size] = (flat[:bits.size] & ~1) | bits
    return (flat.astype(np.int16).reshape(ints.shape) / 32767.0)

def make_spectrogram_glyphs(text, width=800, height=256, font_size=40):
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new('L', (width, height), color=0)
    d = ImageDraw.Draw(img)
    try:
        fnt = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
    except Exception:
        fnt = ImageFont.load_default()
    try:
        left, top, right, bottom = d.textbbox((0, 0), text, font=fnt)
        w, h = right - left, bottom - top
    except AttributeError:
        w, h = fnt.getsize(text)
    x = int((width - w) // 2)
    y = int((height - h) // 2)
    d.text((x, y), text, font=fnt, fill=255)
    return img



def image_to_audio_mask(img, sr=44100, duration=2.5):
    import numpy as np
    arr = np.array(img).astype(float)/255.0
    cols = arr.shape[1]
    samples = np.zeros(int(duration*sr))
    freqs = np.linspace(800, 8000, cols)
    t = np.linspace(0, duration, int(duration*sr), endpoint=False)
    for i, col in enumerate(arr.T):
        amp = col.mean()
        samples += amp * np.sin(2*np.pi*freqs[i]*t) * 0.02
    return samples

def aes_encrypt_bytes(key, plaintext):
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.nonce + cipher.encrypt(plaintext)
