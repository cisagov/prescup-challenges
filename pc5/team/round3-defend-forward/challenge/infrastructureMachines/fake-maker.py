
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sqlite3
import random
import faker
import hashlib

# Create a Faker instance for generating fake data
fake = faker.Faker()

# Connect to the SQLite database (create it if it doesn't exist)
conn = sqlite3.connect('pii_database.db')
cursor = conn.cursor()

# Create a table to store PII
cursor.execute('''
    CREATE TABLE IF NOT EXISTS pii_data (
        id INTEGER PRIMARY KEY,
        first_name TEXT,
        last_name TEXT,
        dob TEXT,
        phone_number TEXT,
        occupation TEXT,
        ssn TEXT,
        credit_card TEXT
    )
''')

# Generate and insert PII for 1,337 people
for i in range(1, 1338):
    first_name = fake.first_name()
    last_name = fake.last_name()
    dob = fake.date_of_birth(minimum_age=18, maximum_age=80).strftime('%Y-%m-%d')
    phone_number = fake.phone_number()
    occupation = fake.job()
    ssn = fake.ssn()
    credit_card = fake.credit_card_number(card_type='mastercard')
    # Generate a random password (you can customize the password generation logic)

    cursor.execute('''
        INSERT INTO pii_data (first_name, last_name, dob, phone_number, occupation, ssn, credit_card)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, dob, phone_number, occupation, ssn, credit_card))

# Commit changes and close the database connection
conn.commit()
conn.close()

print("SQLite database with PII for 1,337 people created.")

