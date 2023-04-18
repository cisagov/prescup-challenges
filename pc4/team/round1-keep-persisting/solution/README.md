# Keep Persisting!

_Solution Guide_

## Overview

In this challenge, there are four persistence mechanisms that deface the "Policies and Procedures for First Contact" website. This solution guide walks you through removing the persistence mechanisms found on your web server and performing a backup to get it up and running again. 

All answers for this challenge are generated dynamically. The format for the answers is a random 16-character hexadecimal, for example: `39e0a53eb1d4d90b`.

>To understand this solution guide better, you need basic knowledge of the following software/skills: CLI, ssh keys, systemd, cronjobs, and shell scripts.

## Question 1

### Removing SSH public key authentication persistence

1. From the `responder` VM, send the website backup (found on the Desktop) to your web server. You can perform this step whenever you want, but it will be easier to already have the backup in the web server. You can use `rsync` or `scp` to achieve this. Here's an example using `rsync`:

```bash
rsync -ar ~/Desktop/backups user@10.5.5.130:~/Desktop/
```

2. Log into the web server with the provided credentials. 

```bash
ssh user@10.5.5.130
password: tartans
```
3. Once logged in, there are **four different methods of persistence** found in the web server that you need to remove. Remove this one first. Skipping it allows the attacker to re-inject the persistence mechanisms to the web server. 

4. The first persistence you need to remove is the one erasing the attacker's public SSH key from your web server. This prevents the attacker from having SSH public key authentication. Navigate to the following directory:

```bash
cd /home/user/.ssh/
```
5. Open the `authorized_keys` file with your editor of preference and you'll immediately notice that the attacker shared his public key with the web server; allowing them access to your web server without needing a password. Remove this SSH key and save the file.

   Here's an example of an easy way to remove everything on that file. Only use it if the attacker's SSH key is the *only* one shared; if there is more than one key, enter the file and remove it manually.

```bash
echo "" > authorized_keys
```

6.  Now that you've removed the attacker's SSH public key from your web server, you can start finding the remaining three methods of persistence. We'll start with the Cron persistence.

## Question 2

### Removing Cron persistence

Cron Job is a Linux command used to schedule tasks periodically such as running scripts every few minutes or once a week. Knowing this, we can start by looking at the web server's `crontab` to see if there are any "out of the ordinary" tasks being triggered. 

1. Access the web server crontab with the following command: 

```bash
crontab -e
```

2. Scroll to the bottom of the crontab. Notice that there are two commands being triggered every minute. Here are the commands and some explanation of what they are doing:

```bash
## The command below is removing the content from your web server every minute. 

* * * * * rm -rf /var/www/html/* 

## And the command below is waiting one second, and then, copying something, from a directory, to your web server directory every minute. Let's write that directory down and see what we can find. 

* * * * * ( sleep 1; cp -r /tmp/p2wj96/* /var/www/html/ )
```

3. To avoid crontab from consistently triggering the commands above, erase them and save the crontab. 

4. Based on what you found on the web server's crontab,  go to `/tmp/` directory. Here, there are two files and one directory to investigate:

   `cron_executable.sh`

   ``defacecron`

   `p2wj96/`

5. Remove all of those files. You can do it in just one line:

```bash
rm -rf p2wj96 defacecron cron_executable.sh
```

Once you remove the cron persistence-related files, directories, and lines from the web server's crontab, you have completely removed another method of persistence. 

## Question 3

### Remove Systemd persistence

Another way of scheduling tasks/jobs is by using **systemd timers**.  Systemd timers are unit files (with a  .`timer` extension) that control a service. These "timers" must have a corresponding `.service` file with the exact same name. An example of a service and a timer is: `startup.service` and `startup.timer`. 

1. Run the following commands. Notice there are no "out of the ordinary" services or timers running at the "privileged" level.

```bash
systemctl list-units --type=service
systemctl list-units --type=timer
```
2. Systemd services and timers don't always need to run at the "privileged" level; they can run at the user  level. Verify which services or timers are running by typing the following command: 

```bash
systemctl list-units --user --type=service
systemctl list-units --user --type=timer
```
3. Notice there is a service unit called `WICKED.service` that has its own timer called `WICKED.timer` and the description for both says "DEFACING WEBSITE". 

4. Run the following to see how often the timer is running: 

```bash
systemctl list-timers --user
```

5. Systemd units run at the user level are written to the directory: `~/.config/systemd/user/`. See what's in that directory.

```bash
cd ~/.config/systemd/user/
ls 
```
6. There are two files and two directories. View the contents of the files first - starting with `WICKED.timer`.

```bash
cat WICKED.timer
```

```bash
## The output of this file should look like this: 

[Unit]
Description=DEFACING TIMER
[Timer]
Unit=DEFACE.service
OnBootSec=5
OnCalendar=*-*-* *:*:00
[Install]
WantedBy=timers.target
```

Now, this file (`DEFACE.timer`) tells you every minute it will trigger the `DEFACE.service` unit. So, if we now `cat` the unit `DEFACE.service`:

```bash
cat DEFACE.service
```
```
## The output of this file should look like this: 

[Unit]
Description=DEFACING WEBSITE
After=network.target
StartLimitIntervalSec=0
[Service]
ExecStart=/bin/bash /home/$USER/.config/systemd_script.sh
[Install]
WantedBy=default.target
```

`DEFACE.service` triggers a script called `systemd_script.sh` found in: `/home/$USER/.config/`. We'll circle back to that file, but first, let's see if there is any other relevant content withing the two directories we saw earlier. 

In the same directory where you found those two unit files, you have a directory named `default.target.wants` and another one named `timers.target.wants`. In them, you will find symbolic links to the same units you saw earlier (`WICKED.service` and `WICKED.timer`). Think of `symbolic links` as shortcuts to the units.

7. Remove any unit files related to the persistence within `~/.config/systemd/user/` and their `symbolic links`. Navigate to the directory you discovered before (`/home/$USER/.config/`) and see what else you find. To remove them, from within `~/.config/systemd/user/` , enter the following command: 

```bash
rm -rf WICKED.service WICKED.timer default.target.wants/WICKED.service /timers.target.wants/WICKED.timer

cd ~/.config/
ls
```

8. Within the `~/.config/` directory, you will see the following "relevant" file and directory: 

​	`deface/`

​	`systemd_script.sh`

    `systemd_vicious.sh`

9. Remove all of them with the following command: 

```bash
rm -rf deface systemd_script.sh systemd_vicious.sh
```

Once you stop services and timers and remove all systemd persistence-related files and directories, you have completely removed another method of persistence. 

## Question 4

### Remove Bashrc persistence

Maybe not the hardest method of persistence to find, but you won't solve this one unless you exit and ssh again to the web server. If you fix the website before finding and fixing this method of persistence, every time you exit the web server and SSH again, the website gets defaced. Something is being triggered every time an interactive shell is opened.

1. The files that control what happens when a bash shell is opened in a Ubuntu web server, `.profile` or `.bashrc`. Those files can be found in the `~/home/user/` directory. Use the following command in the web server to see them. 

```bash
cd /home/user/

ls -la
```
3. Open the `.profile` file. `.profile` file triggers when an `interactive login shell` is used and `.bashrc` triggers every time a new terminal window opens. You already know that if you ssh in, your website gets defaced. This may mean `.profile` might hold the answer for this part of the challenge.

```bash 
cat .profile
```

4. Notice that nothing is "out of the ordinary"; but, `.profile` also calls `.bashrc`. You can see that from within `.profile`, and it should look something like this: 

```
# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
```

5. Because of this, let's  look at the contents of `.bashrc`: 

```bash
cat .bashrc

## If we scroll to the end of this file, you will notice that the following script is being triggered every time a new shell is opened

/var/tmp/sinister_profile.sh
```

6. Remove that line from the file and then save it so it doesn't keep being triggered. Do this with the text editor of your choice. Go to the directory where `sinister_profile.sh` is found:

```bash 
cd /var/tmp/

ls
```

7. The file (`sinister_profile.sh`) being called by `.bashrc`. Open it. The script is removing the contents your web server and replacing them with something found on the `x4sa24/` directory. There is another file called `lousybashrc.sh` that seems to be the one adding the line to `.bashrc`. Remove every file and directory related to the persistence. You can do it with one command: 

```bash
rm -rf lousybashrc.sh sinister_profile.sh x4sa24 
```

Once you remove all the bashrc persistence-related files, directory, and line that triggers those scripts from `.bashrc`, you have completely removed the last method of persistence. 

## Restoring your website

Once every method of persistence is removed use the provided backup to restore your website. This solution guide assumes you already have the backup on your web server's Desktop. 

```bash
## Navigate to /var/www/html/ and make sure that the directory doesn't have any trace of the defaced content. 

cd /var/www/html/
ls

## If it has any files related to the deface content, remove them. 

rm -rf /var/www/html/*

## Finally, assuming your backup is on the web server's desktop, use the following command to copy everything over. 

cp -r ~/Desktop/backups/html_2022/* /var/www/html/
```

Browse to `https://challenge.us` to grade this challenge. Every answer is a random 16-character hexadecimal value.
