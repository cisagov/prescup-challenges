import requests, random, time

def generate_lab_batch():
    return [{
        "patient_id": random.randint(1000, 9999),
        "test_type": random.choice(["CBC", "Blood Panel", "Glucose", "COVID"]),
        "result": random.choice(["normal", "abnormal", "critical"]),
        "unit": random.choice(["mg/dL", "mmol/L", "IU/L"]),
        "value": round(random.uniform(0.1, 200.0), 2),
        "status": "completed"
    } for _ in range(100)]

while True:
    try:
        batch = generate_lab_batch()
        res = requests.post("http://hospital_server/record", json=batch)
        res = requests.post("http://log_server:9000/log", json=batch)

        print(f"[Lab] Sent {len(batch)} tests: {res.status_code}")
    except Exception as e:
        print("[Lab] Error:", e)
    time.sleep(15)
