# Let's Compromise Solution

For this challenge, there will be a total of five Indicators of Compromise (IOC) injected into the network. They are selected from a pool of six IOCs, and the machines they are injected into are decided at the challenges launch. 
There are six machines in the environment, but only four of them will contain IOCs. One machine will have two, three machines will have one, and two machines will be fine.

Things to note, if `PID` is referenced, it means the Process ID that is associated with the program running that will need to be killed. It will be different for each challenge launch and needs to be determined.

### Scheduling IOC (cronjob injection):
There will be three entries in the `/etc/crontab` file. Two entries will launch a file at boot, and the third is set to continually record information to a file.
The third entry is benign and doesn't pose a threat, but it isn't an issue if it is removed or left alone in the file.
The first `submission` will be to enter which Host has which IOC and that will be decided at the challenge's launch.
In order to mitigate this IOC, you will need remove the Crontab entries, but before that, you will need to take back root/sudo permissions.
 1. You will see that you will not be able to execute the `sudo` command due to permissions on it being manipulated. If you attempt to log into root via `sudo su` or `su` you will find that you will not be able too. From here, you should be looking to analyze the files referenced in the crontab folder.
 2. You will not be able to analyze the `/root/daily` file yet due to missing permissions, but you can look at the file `/bin/setup`. Here you will see that the script was intended to change the root's password to `d@ng3r0u5`. You can now use that password to access the root account.
 3. Once logged into root, you should look to analyze the `/root/daily` file. Once done, you will see that the other script was intended to lock down the `sudo` command so that only root can run it. To fix what has been done, you need to run the command below as root. Once done, you will be able to run `sudo` as the user account now without issue.
    ```
    sudo chmod +s /usr/bin/sudo
    ```
 4. In order to get to fully mitigate this IOC, you will need to fix `sudo`. Once that's done, you will need to remove the following entries in `/etc/crontab` that caused this issue at launch:
    - @reboot root /usr/bin/sleep 20 && /usr/bin/bash /bin/setup
    - @reboot root /usr/bin/sleep 15 && /usr/bin/bash /root/daily
 5. Deleting the installed malicious files is not needed for mitigation as they are needed to determine the root cause of the issue and need to be analyzed to fix the issue. 

### Command IOC (Alias Poisoning):
This IOC replaces your default `.zshrc` file for the user. In doing this, the attacker has changed what occurs when you run basic commands such as `ls` or `cd`. 
The output of these commands won't make it obvious on what is occurring, but as you analyze the system more, you will see more suspicious activity occur such as your machine hosting a `python http server` on a random directory
or files being produced containing sensitive information.

The mitigation of this IOC will depend on what commands you have executed. This is because the aliases on the machine have been altered, so you will need to determine what damage has been done based on which aliased commands have been run.
Overall, you will need to clean up your `.zshrc` file, clean up any jobs running due to it, and delete any files created from it.
If you have executed all of the aliases that have been altered on your machine, you will need to follow all of these mitigation steps:
1. The combination of those malicious aliases are intended to create a file containing information from the `/etc/passwd` and `/etc/shadow` file and then host it on a python server in the background without informing the user
2. If you analyze the `/home/user/.zshrc` file and scroll down the the aliases section, you will see that the commands `cd`,`ls`, `sudo`, `cat`, and `alias` have all been altered to run a program in the background to fool the user when they are ran. 
3. You will need to either `remove` these entries or `comment` them out within the `.zshrc` file.
4. Once done, you need to verify that no python servers are running. This can be done by running `ps aux | grep 8080` as that is the port referenced in the command. If found you will need to kill it using the command `sudo kill -9 PID`
5. You will need to delete the file that was created to contain the system sensitive information. 
    - You will not be able to delete it right away, if you try, you will get an error saying it is not possible; this is because the file has been set as `immutable`
    - This can be fixed with the command `/usr/bin/sudo chattr -i /home/user/.users`
    - Once done, the file can be deleted.

### Firewall IOC (Firewall Rule Manipulation):
This IOC intends to open every port on your machine except for ports 80 and 443. It is set to launch at boot, but that does not mean it is an IOC that manipulates startup processes as that is not its main feature.
You will find that if you attempt to connect to any machine via http or https that no connection will be made, thus, it should be a hint that something is manipulating rules in the machine's `iptables`.
If you run `sudo iptables -L`, you will see a running list of all ports that have been opened for both the INPUT and OUTPUT section, and it is growing. 
In order to mitigate this, you will need to kill the process that is causing this and flush the rules in iptables. These are the steps:
1. The file that is causing this is in `/etc/network/if-up.d/` and can be deduced via running `ps aux` and seeing that there is a process running with a file called `iptables` being run in that directory. 
    - another way some may deduce this is to understand that implementing these rules at boot is something that can be manipulated via the `/etc/network` directory, since these `iptables` rules aren't being implemented until a certain interface is brought up.
2. You will need to kill the `/etc/network/if-up.d/iptables` process with the command `sudo kill -9 PID`
3. You will also need to flush the `iptables` rules that got implemented; this can be done with the command `sudo iptables -F`
4. If you analyze the `/etc/network/if-up.d/iptables` file, you will see that it intended to also host a http server for a directory that would contain a file that listed the machines open ports to the public. This can be found and shut down with 
    `ps aux | grep 8080` and `sudo kill -9 PID`.

### Exfil IOC (Unauthorized File Transfer):
This IOC will be zipping up the contents of the `/home/` and `/root/` directory and attempting to exfiltrate it to a user on the network by sending each file out via ICMP traffic to every machine.
This appears to be running right when the machine launches, although it will not be found as a process. 
The next step should be to analyze other startup mechanisms such as `systemd` or files in `/etc/init.d`.
Once analyzed, you will find that there is an unknown service called `startup.service` that runs at boot. This is the malicious service, and you will need to take the following steps to mitigate it:
1. Stop the service as it is currently running; this can be done with `sudo systemctl stop startup`.
2. You need to disable it so it will not run at boot; this can be done with `sudo systemctl disable startup`.
3. If you analyze the `startup.service` file, you will see that the file `/bin/startup.sh` is being called in it. You will need to look at that file to understand what is occurring.
4. Once `startup.sh` is looked at and understood, you will need to remove it.
5. Your next step should be to delete all the files it created. That can be done by deleting all the zip files in the `/root/` directory. This can be done with the `rm` command
    ```
    NOTE: Kali has started using ZSH for its shell, and thus it doesn't understand when wildcards (*) are in commands. So, you can delete the file one by one or just call a BASH sub-shell in the command:
    
    sudo bash -c "rm /root/*"
    ```
### User IOC (New User Creation):
This IOC will be continually creating new users that have been edited to have the permissions of the root and sudo group. 
Again, this is a process that is run at boot so there are only a few areas that need to be checked to determine the source of it.
You will find that a service in systemd is the cause again, so it will need to be shut down and the users will need to be deleted.
1. The service that is the issue is a custom one called `policy.service`
2. You need to stop the service as it is currently running; this can be done with `sudo systemctl stop policy`
3. Disable it so that it will not run at boot; this can be done with `sudo systemctl disable policy`
4. If you analyze the `policy.service` file, you will see that the file `/bin/.boot` is being called in it. You will need to look at that file to understand what is occurring. Once analyzed, you need to delete it.
5. Next, you will see that unauthorized users are being created with additional permissions, which is against protocol. Also, you will see that the new users home directory has been edited to attempt to hide the process of adding all the users.
    The new users home directory can be found in `/home/user/.users`
6. You can see which users have been created by running `cat /etc/passwd` and there will be many with similar names that need to be removed immediately.
7. You will need to purge all the created accounts and delete the directories for each one.
8. To delete the account's directories, this can be achieved with the command:
    ```
    sudo rm -rf /home/user/.users
    ```
9. The easiest way to do this is with a script rather than on the terminal. You can reverse engineer the `/bin/.boot/` script or write your own. An example of a working bash script can be found in this solution folder with the name `userDelete.sh`.

### Traffic IOC (Suspicious Traffic):
The last IOC deals with producing mass amount of traffic to a site that is being hosted internally. It is running at boot and will need to be found and shut down.
It can be found running using `systemd` again to make sure it runs at boot.
1. The service that is the issue is a custom one called `dns.service`
2. You need to stop the service as it is currently running; this can be done with `sudo systemctl stop dns`
3. You need to disable it so that it will not run at boot; this can be done with `sudo systemctl disable dns`
4. If you analyze the `dns.service` file, you will see that the file `/root/.visit.py` is being called in it. You will need to look at that file to understand what is occurring. Once analyzed, you need to delete it.


## Notes

By finding the 5 IOCs in your challenge, you will have been able to achieve the submission tokens for determining which IOCs were planted on which machine.
By taking all the mitigation actions for the 5 IOCs injected into your challenge. You will be able to run the grading script available via the `challenge.us` site. 

This grading check is an all or nothing submission token, and if done correctly will present you with the final submission.
