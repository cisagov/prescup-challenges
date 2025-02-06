# Disservice Station

The **Jiffy Car Repair Company** just launched a web portal for customers to check service schedules and upload insurance and registration information. Secure the new website by implementing three vulnerability fixes.

**NICE Work Roles**

- [Incident Response](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1118](https://niccs.cisa.gov/workforce-development/nice-framework): Identify vulnerabilities
- [T1119](https://niccs.cisa.gov/workforce-development/nice-framework): Recommend vulnerability remediation strategies
- [T0077](https://niccs.cisa.gov/workforce-development/nice-framework): Develop secure code and error handling.
- [T1073](https://niccs.cisa.gov/workforce-development/nice-framework): Perform code reviews


## Background

Update the Jiffy Car Repair Company's webpages to make them secure. Specifically, mitigate a SQL injection vulnerability, a file inclusion vulnerability, and a weak password policy.

## Getting Started

Log into the kali machine (`user-box`), then connect via SSH to the webserver at `10.5.5.100` to fix the website in the `/var/www/html/` directory.  In a browser, you can navigate to `10.5.5.100` and see how the page functions.

>**Warning!** Do not change any of the responses returned by the pages ("Registration successful!", "Login successful!", etc.). These responses are used for grading purposes.

Secure the new website by implementing the following three vulnerability fixes:

1. **Question 1:** Fix the SQL injection vulnerability, but do not break any login functionality.

2. **Question 2:** Fix the file inclusion vulnerability, but still allow `.pdf` file types at a minimum to upload.

3. **Question 3:** Implement a strong password policy requiring a minimum of eight (8) characters, one uppercase character, one lowercase character, and one number.
