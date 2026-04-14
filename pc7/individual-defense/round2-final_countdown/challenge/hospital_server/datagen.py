import os
import random
import csv
from faker import Faker

fake = Faker()

# List of fake health conditions
HEALTH_CONDITIONS = [
    "Hypertension", "Diabetes", "Asthma", "COPD", "Cancer", "Anxiety",
    "Depression", "Arthritis", "Migraine", "Heart Disease", "Allergies",
    "Obesity", "Kidney Disease", "Sleep Apnea", "HIV", "Tuberculosis"
]

# Output directory
OUTPUT_DIR = "/data"
NUM_FILES = 100
ENTRIES_PER_FILE = 1000

os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_entry():
    return {
        "name": fake.name(),
        "address": fake.address().replace('\n', ', '),
        "phone": fake.phone_number(),
        "condition": random.choice(HEALTH_CONDITIONS)
    }

print(f"Generating {NUM_FILES} files with {ENTRIES_PER_FILE} entries each...")

for i in range(1, NUM_FILES + 1):
    file_path = os.path.join(OUTPUT_DIR, f"patient_data_{i:03}.csv")
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['name', 'address', 'phone', 'condition']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for _ in range(ENTRIES_PER_FILE):
            writer.writerow(generate_entry())

print(f"✅ Done! Files saved to: {OUTPUT_DIR}")
