# For Pieces of Eight, They'll Steal Your Freight

Stop the space pirates from obtaining our shipping route information by planting a watering hole attack on their vulnerable WordPress site and identifying the traitor.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-operator)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0028)- Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0616](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0616)-  Conduct network scouting and vulnerability analyses of systems within a network.

## Background

Space pirates have been setting up websites where defectors, spies, and other escapees are able to report on, trade, and supply route information and coordinates. Ultimately, we want to put a stop to these space pirates, but we also want to identify any traitors within our own ranks.

You have been given access to a system just outside the perimeter of one of the space pirate networks, unbeknownst to them.

Go to `https://challenge.us/files` from a gamespace resource to download all challenge-specific files and artifacts. It may take a few minutes before the **grading/files** site is available.

## Objectives

1. Run `sudo dhclient eth0` on Samus in order to verify receipt of a valid DHCP address. For the sake of the challenge, the IP that you receive (`123.45.200.201`) will be used to grade the connection in Step 4. ***You should not change or alter this address.*** If you do not receive this IP address via DHCP, you can set it manually as well with `sudo ifconfig eth0 123.45.200.201/16`.
2. Crack the admin user password using the provided wordlist and hash value from the challenge files page; make sure you can access the web page as the admin user (`thespacepiratebay.org`). 
3. Use the generalized information provided within the GitHub vulnerability page to gain remote access to the underlying WordPress system. This level of access may come in handy in the future.
4. Modify Ridley's "Call to Arms" post to include a malicious payload link at the "Connect With Me" link he originally posted. For the purposes of the challenge, the remote client's user will automatically click on, download, and execute this payload/executable. To verify your link and initiate the connection, execute the grading check on the challenge website.
5. Lastly, once you have a connection with remote shell access to the client, search the traitor's (not "user") files and recover the flag file's token. 

## Challenge Questions

1. What is the cracked password for the user Ridley?
2. What is the token found on the webserver with the Wordpress site files?
3. What is the token provided from the grading server for successfully replacing the Connect With Me link in the blog post?
4. What is the obfuscated token string found on the client system within the traitor's home directory contents?

## Grading Check

Grading the updated link and accessible payload is initiated at: `https://challenge.us` (`https://10.5.5.5`). This check will take a moment to complete. Please refresh the grading page after a few seconds to get your results. If the check passes, a follow-on script will execute your payload on the client. If you need to replace your payload file due to a connection failure, you should rerun the grading check to ensure the client downloads the latest version. If you are confident that your payload is accurate, but did not receive a connection, rerun the grading check again to attempt a new connection.
