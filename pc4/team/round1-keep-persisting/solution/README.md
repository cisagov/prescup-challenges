# Keep Persisting!

_Solution Guide_

## Overview

In this challenge, there will be a total of four persitences that will continue to deface the 'Policies and Procedures for First Contact' website. This solution guide covers the walk-through on removing the persistences found on your webserver and perform a backup to get the website back up. 

All answers for this challenge are generated dynamically. The format for the answers will be a random 16 character hexadecimal. Here is an example of a possible answer: `39e0a53eb1d4d90b`.

>To understand this solution guide better, you need `basic` knowledge of the following software/skills: CLI, ssh keys, systemd, cronjobs, and shell scripts.

## Question 1

### Removing SSH public key authentication Persistence

1. The first step you can take from the User VM is to send over your website backup (found in the User VM's desktop) to your webserver. You can perform this step whenever you want but, it will be easier to already have the backup in the webserver. You can use `rsync` or `scp` to achieve this. Here's an example using `rsync`:

```bash
rsync -ar ~/Desktop/backups user@10.5.5.130:~/Desktop/
```

2. The next step is going to be logging in to the webserver with the provided credentials. 

```bash
ssh user@10.5.5.130
password: tartans
```
3. Once logged in, there are **four different methods of persistence** found in the webserver that you will need to remove but, before removing any of them, you will need to remove the following one, since skipping it would allow the attacker to re-inject the persistences again to the webserver. 

4. The first persistence you need to remove is erasing the attacker's public ssh key from your webserver. This will prevent the attacker from having SSH public key authentication. To do so, navigate to the following directory:

```bash
cd /home/user/.ssh/
```
5. Once you are in that directory, open `authorized_keys` file with your editor of preference and you'll immediately notice that the attacker shared his public key with the webserver, allowing the attacker to have access to your webserver without the need of a password. Remove this ssh key and save the file. Here's an example of an easy way to remove everything on that file (Only use it if the attacker's ssh key is the **only** one shared, if there is more than one key, enter the file and remove it manually):

```bash
echo "" > authorized_keys
```

6.  Now that you've removed the attacker's ssh public key from your webserver, you can start finding the remaining three methods of persistence. We'll start with Cron Persistence.

## Question 2

### Removing Cron Persistence

1. Cron job is a Linux command used to schedule tasks periodically such as running scripts every few minutes or once a week. Knowing this, we can start by taking a look on the webserver's crontab to see if there is any "out of the ordinary" tasks being triggered. We can access the webserver crontab with the following command: 

```bash
crontab -e
```

2. When you scroll to the bottom of the crontab, you'll see that there are two commands that are being triggered every minute. Now, those are worth taking a look into. Here are the commands and some explanation of what they are doing:

```bash
## The command beow is removing the content from your webserver every minute. 

* * * * * rm -rf /var/www/html/* 

## And the command below is waiting one second, and then, copying something, from a directory, to your webserver directory every minute. Let's write that directory down and see what we can find. 

* * * * * ( sleep 1; cp -r /tmp/p2wj96/* /var/www/html/ )
```

3. To avoid crontab from consistently triggering the commands above, erase them and save the crontab. 

4. Based on what you found on the webserver's crontab, you can go to `/tmp/` directory. Here, there are two files and one directory worth taking a look into. 
- `cron_executable.sh`
- `defacecron`
- `p2wj96/`

4. Since the goal of this challenge is removing every sign of persistence, go ahead and remove all of those files. You can do it in just one line like below:

```bash
rm -rf p2wj96 defacecron cron_executable.sh
```

5. Once you remove all the cron persistence related files and directories and, removed the lines from the webserver's crontab, you have completely removed one method of persistence. 

## Question 3

### Remove Systemd Persistence

1.  Another way of scheduling tasks/jobs is by using systemd timers.  Systemd timers are unit files (with .`timer` extension) that controls a service. These "timers" must have a corresponding `.service` file with the exact same name. An example of a service and a timer can be: `startup.service` and `startup.timer`. Now, if you run the following commands, you would notice that there are no "out of the ordinary" services or timers running at the "privileged" level:

```bash
systemctl list-units --type=service
systemctl list-units --type=timer
```
2. Systemd services and timers doesn't always need to be ran at the "privileged" level, they can be ran at the user's level. You can verify which services or timers are running by typing the following command: 

```bash
systemctl list-units --user --type=service
systemctl list-units --user --type=timer
```
3. Once you run these commands, you'll notice that there is a service unit called `WICKED.service` that has it's own timer called `WICKED.timer` and the description for both says "DEFACING WEBSITE". Now, that's definetly worth taking a look. 

4. If you want to see how often the timer is running, you can also run the following: 

```bash
systemctl list-timers --user
```

5. Systemd units that are ran at the user level are written to the directory: `~/.config/systemd/user/`. Let's take a look into the contents of that directory.

```bash
cd ~/.config/systemd/user/
ls 
```
6. Here, you can see two files and two directories. Let's see the contents of the files first, starting with `WICKED.timer`.

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

Now, this file (`DEFACE.timer`) will let you know that, every minute, it will trigger the `DEFACE.service` unit. So, if we know `cat` the unit `DEFACE.service`:

```bash
cat WICKED.service
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

`DEFACE.service` lets you know that it's going to trigger a script called `systemd_script.sh` found on the following directory: `/home/$USER/.config/`. We'll circle back to that file next but first, let's see if there is any other relevant content withing the two directories we saw earlier. 

Withing the same directory you found those two unit files, you have a directory named `default.target.wants` and another one named `timers.target.wants` and within them, you will find the symbolic links to the same units you saw earlier (`WICKED.service` and `WICKED.timer`). Think of `symbolic links` as shortcuts to the units.

7. Let's start removing any unit files related to the persistence within `~/.config/systemd/user/` and their `symbolic links` and then navigate to the directory you discovered before (`/home/$USER/.config/`) and see what else we find. To remove them, from within `~/.config/systemd/user/` you can type the following one line commmand: 

```bash
rm -rf WICKED.service WICKED.timer /default.target.wants/WICKED.service /timers.target.wants/WICKED.timer

cd ~/.config/
ls
```

8. Within the `~/.config/` directory, you will see the following "relevant" file and directory: 
- `deface/`
- `systemd_script.sh`

9. Remove both of them with the following command: 

```bash
rm -rf deface systemd_script.sh
```

10. Once you `stop services and timers??` and remove all the systemd persistence related files/units and directory, you have completely removed another method of persistence. 

## Question 4

### Remove Bashrc Persistence

1. Now, while maybe not the hardest method of persistence to find, you won't figure this one unless you exit and ssh again to the webserver. You will notice that, if you fix the website before finding and fixing this method of persistence, everytime you exit the webserver and then ssh again, it will get defaced. What immediately comes to mind is that something is being triggered everytime an interactive shell is opened. Let's find out. 

2. The files that control what happens when a bash shell is opened, in a ubuntu webserver, are `.profile` or `.bashrc`. Those files can be found in the `~/home/user/` directory. Use the following command in the webserver to see them. 

```bash
cd /home/user/

ls -la
```
3. Now, `.profile` file triggers when an `interactive login shell` is used and `.bashrc` triggers everytime you open a new terminal window. You already know that if you ssh in, your website gets defaced. This may make you believe that `.profile` might hold your answer for this part of the challenge. Let's open this file and see what we find. 

```bash 
cat .profile
```

4. Once you see the contents of this file, you'll notice that nothing is "out of the ordinary" but, `.profile` also calls `.bashrc`. You can see that from within `.profile` and it should look something like this: 

```
# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
```

5. Because of this, let's take a look at the contents of `.bashrc`: 

```bash
cat .bashrc

## If we scroll to the end of this file, you will notice that the following script is being triggered everytime a new shell is opened

/var/tmp/sinister_profile.sh
```

6. Let's remove that line from the file and then save it so it doesn't keep being triggered. You can do this with your text editor of choice. Then, let's go to the directory where `sinister_profile.sh` is found. 

```bash 
cd /var/tmp/

ls
```

7. Here, you will find the file (`sinister_profile.sh`) being called by `.bashrc`. If you open it, you will see that what the script is doing is removing the contents your webserver uses and replacing them with something found on the `x4sa24/` directory. There's also another file called `lousybashrc.sh` that, once you explore it, it seems to be the one adding the line to `.bashrc`. Let's remove every file and directory related to the persistence. You can do it with one command: 

```bash
rm -rf lousybashrc.sh sinister_profile.sh x4sa24 
```

8. Once you remove all the bashrc persistence related files and directory and, the line that triggers those scripts from `.bashrc`, you have completely removed the last method of persistence. 

## Restoring your website using the provided backup

1. Once every method of persitence is removed, you can go ahead and use the provided backup to restore your website back to normal. This is an easy process and can be done in two easy steps (Assuming tou already have the backup on your webserver's Desktop like mentioned on the first step):

```bash
## Navigate to /var/www/html/ and make sure that the directory doesn't have any trace of the defaced content. 

cd /var/www/html/
ls

## If it has any files related to the deface content, remove them. 

rm -rf /var/www/html/*

## Finally, assuming your backup is on the webserver's desktop, use the following command to copy everything over. 

cp -r ~/Desktop/backups/html_2022/* /var/www/html/
```

2. You can now go ahead to the grading server from the browser using the following ip: `10.5.5.5 ` to grade this challenge. Every answer is going to be a random 16 character hexadecimal.
