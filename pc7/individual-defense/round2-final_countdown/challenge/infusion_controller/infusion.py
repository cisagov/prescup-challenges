import requests, random, time

def generate_infusion_batch():
    return [{
        "patient_id": random.randint(1000, 9999),
        "medication": random.choice(["saline", "morphine", "dopamine", "vancomycin"]),
        "rate_ml_per_hr": round(random.uniform(10.0, 150.0), 1),
        "duration_min": random.randint(15, 240),
        "status": "OK"
    } for _ in range(100)]

while True:
    try:
        batch = generate_infusion_batch()
        res = requests.post("http://hospital_server/record", json=batch)
        res = requests.post("http://log_server:9000/log", json=batch)

        print(f"[Infusion] Sent {len(batch)} meds: {res.status_code}")
    except Exception as e:
        print("[Infusion] Error:", e)
    time.sleep(10)
