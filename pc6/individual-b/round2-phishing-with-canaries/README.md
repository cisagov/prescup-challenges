# Phishing With Canaries

Analyze network activity, develop a custom canary tool, and identify key responders from a target list to uncover the final token. 

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/vulnerability-analysis)
- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/exploitation-analysis)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/workforce-development/nice-framework/task/t1359): Perform penetration testing.
- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework/task/t1084): Identify anomalous network activity

## Background

Canary tokens, much like honeypots, are designed to act as early warning systems in cybersecurity. While a honeypot mimics an entire system to attract attackers, a canary token serves as a decoy file, email, or network resource that triggers an alert when interacted with.

## Getting Started

Using the provided Kali machine:

## Part 1

---

### Description:

A user opened a PDF file which triggered an alert. The alert was triggered by unexpected network activity, raising suspicion due to the involvement of strange domains.

Analyze the provided PCAP to determine the cause, identify the suspicious event, and gather key details.

PCAP file(`part_1.pcapng`) is hosted at `challenge.us` in your web browser.

---

### Objective:

Investigate the network traffic and determine what triggered the alert. Use what you learn to conduct an internal security assessment. 

1. **Examine the network capture** for any anomalies.
2. **Identify and trace** unusual activity patterns or external communications.
3. **Document your findings** including key information about the trigger.

---

## Part 2

---

### Description:

Write a custom script that acts as an internal canary token. The script should function as a simple TCP server, logging connection attempts and received data. 

When a user receives an email, the email server will send a HTTP POST request the links found in the email body to simulate a "click".

Use the details from the "System and Tool Credentials" section to perform this task.  

---

### Objective:

1. **Create a Custom TCP Server:**
   - Design a script to listen for incoming connections on a specific host and port. 
   - Log connection attempts, including any data received.

2. **Respond to Incoming POST Requests:**
   - Your server must handle a POST request containing a custom **User-Agent** header.
   - Ensure your script captures and logs relevant details from the request.

3. **Deliver a Phishing Email:**
   - Craft and send a phishing email to the "Test Email Target" via the "Email Server" using tools or scripts available on your Kali Linux machine. 
   - The email must include a URL pointing to your TCP server's internal address (e.g., `http://<your-kali-ip>:<port>`). 
   - Avoid using external services or third-party tools.

4. **Extract the Canary Token:**
   - Analyze your logs to identify and extract the token.

---

## Part 3

---

### Description:

Simulate an internal phishing assessment to identify vulnerable users. From a list of target email addresses, only 5 will trigger a unique response when using your canary script. Send a email to all users in the target list (`part_3.txt`) and identify which ones trigger a unique response. 

Target file(`part_3.txt`) is hosted at `challenge.us` in your web browser.

---

### Objective:

1. **Process the Email List:**
   - Use the provided text file containing target emails.
   - Interact with each target to identify which produce a unique response.
2. **Identify the Responders:**
   - Focus on the 5 targets that trigger a UNIQUE response, capturing and logging their details.

---

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|canary-kali|user|tartans|

**Email Server IP:** `10.5.5.87`
**Port:** `1025`
**Test Email Target:** `user0000@internal`

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.