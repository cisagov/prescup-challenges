#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


SMTP_SERVER="123.45.67.89"
SMTP_PORT="25"
FROM_ADDRESS="test@example.com"
TO_ADDRESS="recipient@example.com"

for i in {1..25}; do
  (
    echo "EHLO localhost"
    echo "MAIL FROM:<$FROM_ADDRESS>"
    echo "RCPT TO:<$TO_ADDRESS>"
    echo "DATA"
    echo "Subject: Test Email $i"
    echo "This is test email number $i."
    echo "."
    echo "QUIT"
  ) | telnet $SMTP_SERVER $SMTP_PORT
  echo "Email $i sent."
done

