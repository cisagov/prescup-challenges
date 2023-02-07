# The Party Line

Investigate and remedy a cyber defense incident.

**NICE Work Roles**
- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-incident-responder)

**NICE Tasks**
- [T0041](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0041) -  Coordinate and provide expert technical support to enterprise-wide cyber defense technicians to resolve cyber defense incidents.

## Background

IT administrators noticed some unexpected network traffic and unauthorized applications and services. Additionally, admins can't access the `enterprise-server` because one of the users changed the shared password. 

Examine the users' machines to find evidence of creating unauthorized services on enterprise resources. Find out what the new `enterprise-server` password is.

IRC chat logs and user documents might contain evidence of rogue activities on the network. Users may have tried to cover their tracks by deleting logs. 

The only required services that must remain accessible on the `enterprise-server` are SSH, IRC, and a website hosted on port 80. Other services on the `enterprise-server` should be considered "unauthorized" and should be disabled.

## Getting Started

Using the provided credentials, investigate the user machines to find evidence of starting unauthorized services and attempt to locate the new `enterprise-server` password. Once you gain access to the `enterprise-server`, disable the unauthorized network services the users created.  

Answer questions 1 through 5 displayed below. To get the token for question 6, you must first disable the unauthorized network services and then go to `https://challenge.us` from a gamespace resource. Click the Grade Challenge button and wait for the result. You will be provided with either a failure message or a success message with the token for question 6.  

Note: If you need to crack passwords on encrypted files, try using the word list provided on the Kali machine's CDROM drive; these are the most common passwords used to secure files on our network. The word list is not effective on user account passwords. 

## Questions

1. What is the first and last name of the user that attempted shell access to the enterprise-server (10.5.5.160)?
2. What is the password of the "user" account on the enterprise-server?
3. What is the first and last name of the user that ran the application that was shared via the unauthorized service?
4. What is the value written after the text "License Key: " that is visible in the file that is sent at the request of one of the users?
5. The unauthorized application that was shared on the network appears to try contacting other machines when executed. The value being sent over the network from the application is encrypted and encoded. The decoded and decrypted text is the token.
6. Finally, you must prevent users from accessing any unauthorized applications or services without disrupting the chat and web server services. This will determine if the appropriate remediation steps have been completed and provide the final token.
