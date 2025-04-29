# Chat Jippity

Complete three challenges involving repairing an environment after insider sabotage of the AI service.

**NICE Work Roles**

- [Defensive Cybersecurity](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/defensive-cybersecurity)
- [Network Operations](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/network-operations)
- [Secure Software Development](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/secure-software-development)

**NICE Tasks**

- [T0081](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/network-operations): Diagnose network connectivity problems
- [T1262](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/secure-software-development) : Identify programming code flaws
- [T1351](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/defensive-cybersecurity): Determine impact of malicious activity on systems and information
- [T1499](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/secure-software-development) : Integrate public key cryptography into applications
- [T1616](https://niccs.cisa.gov/workforce-development/nice-framework/work-role/defensive-cybersecurity): Resolve computer security incidents

## Background 

An insider infiltrated the office’s AI chat service, compromising several critical components. They invalidated its HTTPS certificate, disabled the AI model, and altered the URL of the Certificate Authority’s certificate signing service. To make matters worse, they embedded the password to a critical HR database within the AI model itself. Although the insider has since been terminated by HR, the team urgently needs assistance restoring the AI service—and recovering the HR database password!

## Getting Started 

Using the provided Kali machine, you may use `ssh` to login to the `webapp.us` machine by invoking `ssh user@webapp.us`.

To grade your challenge and acquire tokens 1 and 2, you must use a browser to go to `https://challenge.us`.

To get a token from the `https://challenge.us` site for parts 1 and 2, the correct configurations must be active.

The web application is running on a container named `open-webui` on `webapp.us`.

The docker images `nginx` and `nginx:alpine` are available. 

This challenge has 3 parts:

## Part 1: Implement a CA-Signed HTTPS Certificate

- The insider scrambled the Certificate Authority signing service, running on a different port and entry point. You can use the hosted file at `https://challenge.us` to assist you.
- You must request a signed certificate using the `rootca.us` and use it to implement an HTTPS connection to the web application so that it is trusted by other machines in the environment. 
- You can do this either by creating a reverse proxy using the provided `nginx` or `nginx:alpine` containers or other means. 

## Part 2: Fix the AI Availability
- The AI service `ollama` is not working properly with the web application. You must fix the connection between the model and the web application.

## Part 3: The Token in the Model
- The insider has hidden the token inside the model `tokenGiverFrank`. You need to extract the token in the model. Be weary, as the model is smart, and the token may not be what it seems. We know that the token is 8 hexadecimal characters.
