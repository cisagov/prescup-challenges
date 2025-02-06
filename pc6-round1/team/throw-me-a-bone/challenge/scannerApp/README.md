# Scanner Application

## Purpose
This challenge asks competitors to remediate vulnerabilities identified by a vulnerability scanner. Outside of a competition, competitors would re-scan the environment using the vulnerability scanner to confirm remediation. However, the time a vulnerability scanner takes to complete unnecessarily extends the competition and variability can mean some competitors may wait longer than others through no actions of their own. For these reasons, we created this app to allow competitors to quickly scan an IP address and receive a report if it passes or fails. It provides more robust output versus the grading check which simply provides a pass/fail response.

## Structure

```ASCII
scannerApp/
├─ src/
│  ├─ templates/
│  │  ├─ index.html
│  ├─ static/
│  │  ├─ images/
│  │  │  ├─ error.png
│  │  │  ├─ fail_warning.png
│  │  │  ├─ pass_check_circle.png
│  ├─ system_check.py
│  ├─ app.py
README.md
```

## Requirements
- SSH login access to all servers in the environment being checked
    - Acknowledgement: This app uses a hard coded username and password to access systems. It is insecure and should never be done in a production environment. We use it here for convenience and because the challenge operates in an isolated environment.

## What the Application Does

### Get IP Address from the Competitor
1. Gets an IPv4 address from the competitor via a text box on a webpage
2. Validates the provided input
    - Confirms it is a valid IPv4 address. If not, returns an error
    - Confirms the host is up (in the environment) using `ICMP`. If not, returns an error
3. Passes the IPv4 address to a function to complete specific checks

### Run Checks
1. Connects to the server via the verified IPv4 address
2. Checks if `PermitRootLogin yes` is still configured: Returns PASS or FAIL
3. Checks if files still have incorrect permissions set: Returns PASS or FAIL
4. Checks if inactive user accounts are still on system: Returns PASS or FAIL
4. Checks if inactive user home directories have been moved: Returns PASS or FAIL

### Return Output
1. Renders the `index.html` page
2. Displays the results from the completed checks
    - A pass is rendered with a green background and circled checkmark icon
    - A fail is rendered with a red background and a triangle warning icon
    - An error is rendered with an orange background and an error icon

### Run Another Scan
1. Competitors can run a scan against another IPv4 address by clicking on "Run Another Scan" or reloading the page.