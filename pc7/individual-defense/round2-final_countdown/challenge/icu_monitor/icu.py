import requests, random, time

def generate_icu_batch():
    return [{
        "patient_id": random.randint(1000, 9999),
        "heart_rate": random.randint(55, 140),
        "oxygen_saturation": random.randint(85, 100),
        "respiratory_rate": random.randint(12, 30),
        "blood_pressure": f"{random.randint(90, 180)}/{random.randint(60, 110)}",
        "status": "stable"
    } for _ in range(100)]

while True:
    try:
        batch = generate_icu_batch()
        res = requests.post("http://hospital_server/record", json=batch)
        res = requests.post("http://log_server:9000/log", json=batch)
        print(f"[ICU] Sent {len(batch)} vitals: {res.status_code}")
    except Exception as e:
        print("[ICU] Error:", e)
    time.sleep(5)
