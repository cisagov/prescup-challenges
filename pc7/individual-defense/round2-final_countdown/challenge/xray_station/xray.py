import requests, random, time

def generate_xray_batch():
    return [{
        "patient_id": random.randint(1000, 9999),
        "image_id": f"XR-{random.randint(100000, 999999)}",
        "body_part": random.choice(["chest", "abdomen", "head", "limb"]),
        "resolution": f"{random.choice([256, 512, 1024])}x{random.choice([256, 512, 1024])}",
        "format": random.choice(["DICOM", "JPEG", "PNG"]),
        "status": "uploaded"
    } for _ in range(100)]

while True:
    try:
        batch = generate_xray_batch()
        res = requests.post("http://hospital_server/record", json=batch)
        res = requests.post("http://log_server:9000/log", json=batch)
        print(f"[XRay] Sent {len(batch)} items: {res.status_code}")
    except Exception as e:
        print("[XRay] Error:", e)
    time.sleep(10)
