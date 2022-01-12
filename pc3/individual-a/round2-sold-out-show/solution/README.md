# Sold Out Show: Solution

## Overview

DC was compromised by a golden ticket attack. The competitor must navigate through the attack and find the corresponding tokens in the DC.

## Tools used

- Windows Event Viewer
- Wireshark
- Powershell (to query WMI)

## Steps to Solve

### Question 1: Find the user using the golden ticket

- Open Windows Event Viewer
- Find a Kerberos login event
- Look into the user field, find the user

### Question 2: Investigate the uploader EXE. Visit the site the file is uploading to

- Open Wireshark
- Capture traffic on the correct NIC
- Run the uploader.exe
  - Should be HTTP traffic going to the uploading site
- View the pcap, find the site it's uploading to
- Visit the site at {site}.com/get-tickets, get the token

### Question 3: Investigate the WMI persistence left behind. Find the token

- Query WMI __EventFilter, __ConsumerEvent
  - In Powershell:
    - Get-WMIObject -Namespace root\Subscription -Class __EventFilter
    - Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
    - Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
- Find the token within the object
  - "token: {token-here}"

### Question 4: Find what is leaking the ntds.dit file and fix it. Run the grading script by visiting challenge.us

- Disable the Task "AD Backup"
- Visit challenge.us
- Run the grading script
  - Should come back with the token
