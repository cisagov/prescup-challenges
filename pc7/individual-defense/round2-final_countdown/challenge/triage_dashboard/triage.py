import requests, random, time

def generate_triage_batch():
    return [{
        "patient_id": random.randint(1000, 9999),
        "complaint": random.choice(["fever", "shortness of breath", "trauma", "seizure"]),
        "priority": random.choice(["low", "medium", "high"]),
        "nurse_station": random.randint(1, 10),
        "status": "triaged"
    } for _ in range(100)]

while True:
    try:
        batch = generate_triage_batch()
        res = requests.post("http://hospital_server/record", json=batch)
        res = requests.post("http://log_server:9000/log", json=batch)
        print(f"[Triage] Sent {len(batch)} patients: {res.status_code}")
    except Exception as e:
        print("[Triage] Error:", e)
    time.sleep(20)
