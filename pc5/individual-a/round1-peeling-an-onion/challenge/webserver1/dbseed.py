
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import sqlite3
from faker import Faker
import hashlib
import random
import subprocess

def generate_users():
    fake = Faker()

    conn = sqlite3.connect('/home/user/diwa/database/db.s3db')
    cursor = conn.cursor()

    # Generate regular users
    for i in range(1, 51):
        user_id = i + 2  # Start from 3 onwards
        username = fake.user_name()
        password = hashlib.md5(fake.password().encode()).hexdigest()
        email = fake.email()
        country = fake.country()
        is_admin = 0
        cursor.execute("INSERT INTO users (id, username, password, email, country, is_admin) VALUES (?, ?, ?, ?, ?, ?)",
                        (user_id, username, password, email, country, is_admin))

    # Generate admin users
    adminpass = subprocess.run(f"vmware-rpctool 'info-get guestinfo.adminpass'", shell=True, capture_output=True).stdout.decode().strip('\n')
    admin_passwords = [hashlib.md5(adminpass.encode()).hexdigest() for _ in range(6)]
    admin_indexes = random.sample(range(3, 53), 10)
    admin_duplicates = random.sample(admin_indexes, 6)

    for admin_id in admin_indexes:
        username = fake.user_name()
        if admin_id in admin_duplicates:
            password = admin_passwords[0]
        else:
            password = hashlib.md5(fake.password().encode()).hexdigest()
        email = fake.email()
        country = fake.country()
        is_admin = 1
        cursor.execute("UPDATE users SET username=?, password=?, email=?, country=?, is_admin=? WHERE id=?",
                        (username, password, email, country, is_admin, admin_id))

    conn.commit()
    conn.close()

if __name__ == '__main__':
    generate_users()
