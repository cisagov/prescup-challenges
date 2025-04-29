# Oh My API

Analyze three web applications and exploit vulnerabilities in their insecure code.  

**NICE Work Roles**
* [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework)
* [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
* [T1619](https://niccs.cisa.gov/workforce-development/nice-framework): Perform risk and vulnerability assessments
* [T1690](https://niccs.cisa.gov/workforce-development/nice-framework): Identify exploitable technical or operational vulnerabilities
* [T1262](https://niccs.cisa.gov/workforce-development/nice-framework): Identify programming code flaws

## Background

You are tasked with conducting a security audit on several small web applications. You will encounter three different web servers, each with their own vulnerability. See if you can analyze and exploit each vulnerability to either gain elevated permissions or access sensitive data. 

## Getting Started

Source code snippets for each of the web servers are available at `challenge.us/files`

## Submissions

**Token 1**: What is the value of the token found in the `token1` file, located at `/home/user/p1/token1` (the same folder as the webserver) on `app1` at `10.5.5.101:8080`. 
 
**Token 2**: What is the value of the token you receive by running the Grading Check at `challenge.us` after you are able to create a new user on `app2` at `10.5.5.102:8081` with a `userId` of `1337` that has admin permissions. 

**Token 3**: What is the value of the token found in the `token3` file, located at `/home/user/p3/token3` (the same folder as the webserver) on `app3` at `10.5.5.103:8082`. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|Kali Linux|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
