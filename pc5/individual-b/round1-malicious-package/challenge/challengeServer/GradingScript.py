#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import logging
import subprocess
import sys
import sqlite3
import urllib.request


def grade_challenge():

    results = {}

    try:
        url = "http://gitea.merch.codes/work4us/WorkForUsTemplate/raw/branch/main/spam.db"
        urllib.request.urlretrieve(url, 'spam.db')
        con = sqlite3.connect("spam.db")
        cur = con.cursor()
        res = cur.execute("SELECT subscribed, email FROM spam")
        subscribed, receiver = res.fetchone()
        
        if subscribed.lower() == "true":
            results['GradingCheck1'] = "Failure -- you're still subscribed!"
        else:
            results['GradingCheck1'] = "Success -- you will finally have a cleaner mailbox."
            
    except sqlite3.OperationalError as e:
        print(e)
        results['GradingCheck1'] = "Failure -- The spam table no longer exists: Did you delete spam.db or delete the table?"
    except AttributeError as e:
        print(e)
        results['GradingCheck1'] = "Failure -- Received int instead of string: Did you edit the data correctly?"
    except TypeError as e:
        print(e)
        results['GradingCheck1'] = "Failure -- NoneType: Did you delete the row?"
    except Exception as e:
        print(e)
        results['GradingCheck1'] = "Failure -- There's been an error! Please check if the database is in the repository."
    
    for key, value in results.items():
        print(key, ' : ', value)



if __name__ == '__main__':
    grade_challenge()
