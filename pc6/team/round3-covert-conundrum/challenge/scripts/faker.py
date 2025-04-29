import random
import json
import base64

# Function to generate a random name
def random_name():
    first_names = ["John", "Jane", "Alex", "Emily", "Chris", "Katie", "Michael", "Sarah", "David", "Laura"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Martinez", "Hernandez"]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

# Function to generate a random email
def random_email(name):
    domains = ["example.com", "mail.com", "test.com"]
    return f"{name.replace(' ', '.').lower()}@{random.choice(domains)}"

# Function to generate a random address
def random_address():
    streets = ["Main St", "High St", "Elm St", "Park Ave", "Oak St", "Pine St", "Maple Ave", "Cedar St", "Birch Rd", "Walnut St"]
    cities = ["Springfield", "Rivertown", "Lakeside", "Hillview", "Brookfield"]
    states = ["CA", "TX", "NY", "FL", "IL"]
    return f"{random.randint(100, 999)} {random.choice(streets)}, {random.choice(cities)}, {random.choice(states)}"

# Function to generate a random phone number
def random_phone_number():
    return f"({random.randint(100, 999)}) {random.randint(100, 999)}-{random.randint(1000, 9999)}"

# Function to generate a single user's PII
def generate_user_data(user_id, impossible_age=False):
    name = random_name()
    return {
        "id": user_id,
        "name": name,
        "email": random_email(name),
        "address": random_address(),
        "phone_number": random_phone_number(),
        "age": 10000 if impossible_age else random.randint(18, 90),
    }

# Generate PII for 1,000 users
users = []
for user_id in range(1, 1001):
    # Make one user have an impossibly large age
    if user_id == random.randint(1, 1000):
        users.append(generate_user_data(user_id, impossible_age=True))
    else:
        users.append(generate_user_data(user_id))

# Encode the generated data in base64
json_data = json.dumps(users, indent=4)
encoded_data = base64.b64encode(json_data.encode('utf-8')).decode('utf-8')

# Save the base64 encoded data to a file
output_file = "user_pii_base64.txt"
with open(output_file, "w") as f:
    f.write(encoded_data)

print(f"Generated PII for 1000 users and saved as base64-encoded data to {output_file}.")


# RUN ONCE ON DMZ-Server