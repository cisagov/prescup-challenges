# Why is the R&D Always Gone?

_Challenge Artifacts_

- [add-ssh-user.sh](./ubuntu-user-sim/add-ssh-user.sh) - Startup script to add user and password (answers to Question 2) to the SSH server.
  - Lines 3 and 4 need configured
- [add-ssh-user.service](./ubuntu-user-sim/add-ssh-user.service) - systemd unit file to launch [add-ssh-user.sh](./ubuntu-user-sim/add-ssh-user.sh)
- [api-placement.sh](./ubuntu-user-sim/api-placement.sh) - Startup script to write API key for Zulip's backup-bot to the SSH server.
  - Line 2 needs configured
- [api-placement.service](./ubuntu-user-sim/api-placement.service) - systemd unit file to launch [api-placement.sh](./ubuntu-user-sim/api-placement.sh)
- [access-ssh.sh](./ubuntu-user-sim/access-ssh.sh) - Startup script that attempts to SSH into the SSH server.
  - Lines 2 and 3 need configured
- [access-ssh.service](./ubuntu-user-sim/access-ssh.service) - systemd unit file to launch [access-ssh.sh](./ubuntu-user-sim/access-ssh.sh) every 60 seconds.
- [router-add-user.sh](./ubuntu-user-sim/router-add-user.sh) - Startup script to SSH into the file server as root and add a new user, if new user does not exist.
- [router-add-user.service](./ubuntu-user-sim/router-add-user.service) - systemd unit file to launch [router-add-user.sh](./ubuntu-user-sim/router-add-user.sh) every 60 seconds.
- [router-add-web.sh](./ubuntu-user-sim/router-add-web.sh) - Startup script to set ipfire admin password to a password found in the [wordlist.txt](./wordlist.txt), if it hasn't been set.
 - Line 2 needs configured
- [router-add-web.service](./ubuntu-user-sim/router-add-web.service) - systemd unit file to launch [router-add-web.sh](./ubuntu-user-sim/router-add-web.sh) every 10 seconds.
- [zulip-poster.sh](./ubuntu-user-sim/zulip-poster.sh) uses the intel-bot's API key to post various chat messages in the Zulip collab thread (including the answer to Question 3).
  - Lines 2, 6 ,8, 10, 12, 14, and 16 need configured
- [zulip-poster.service](./ubuntu-user-sim/zulip-poster.service) - systemd unit file to launch [zulip-poster.sh](./ubuntu-user-sim/zulip-poster.sh)
- [startup-api.sh](./ubuntu-user-sim/startup-api.sh) - Script to set the backup-bot's API key
  - Lines 3 and 6 need configured
- [startup-api.service](./ubuntu-user-sim/startup-api.service) -systemd unit file to launch [startup-api.sh](./ubuntu-user-sim/startup-api.sh)

_Setup_

Users were provided a Kali machine with the IP address of 172.21.3.101/24. The topology is set up as seen [here](./topology.png); however, users should not be given this topology.


## Kali Installation

1. Install cowrie (Steps 1-6) (https://cowrie.readthedocs.io/en/latest/INSTALL.html)

## ipfire 2.25 (Build 155) Installation

1. Set the `root` password to something complex
2. Set the `admin` user to something that can be found in the [wordlist.txt](./wordlist.txt)
3. Login to the ipfire web interface and enable SSH Access and allow for password based authentication
4. Allow any MAC address to connect to Blue in the Wireless Configuration. See [example](./ipfire-2.25-build-155/wireless-configuration.png) 
5. Set your firewall rules to match this [example](./ipfire-2.25-build-155/firewall-rules.png)

## SSH File Server Installation

1. Create an Ubuntu 22.04 LTS Server
2. Place [add-ssh-user.service](./ubuntu-user-sim/add-ssh-user.service), [add-ssh-user.sh](./ubuntu-user-sim/add-ssh-user.sh), [api-placement.service](./ubuntu-user-sim/api-placement.service), and [api-placement.sh](./ubuntu-user-sim/api-placement.sh) in the /etc/systemd/system directory and ensure the .sh scripts have the executable bit set.
3. Cross reference each of these files with the Challenge Artifacts section above and edit any lines, as needed
4. Run the following bash commands to complete system configuration:
```bash
-sudo systemctl start add-ssh-user.service
-sudo systemctl enable add-ssh-user.service
-sudo systemctl start api-placement.service
-sudo systemctl enable api-placement.service
```

## Ubuntu User Sim Installation

1. Create an Ubuntu 22.04 LTS Desktop
2. Install sshpass and curl
3. Assign the IPv4 address and default gateway according to the topology
4. Place [access-ssh.service](./ubuntu-user-sim/access-ssh.service), [access-ssh.sh](./ubuntu-user-sim/access-ssh.sh), [router-add-user.service](./ubuntu-user-sim/router-add-user.service), [router-add-user.sh](./ubuntu-user-sim/router-add-user.sh), [router-add-web.service](./ubuntu-user-sim/router-add-web.service), [router-add-web.sh](./ubuntu-user-sim/router-add-web.sh), [zulip-poster.service](./ubuntu-user-sim/zulip-poster.service), and [zulip-poster.sh](./ubuntu-user-sim/zulip-poster.sh) in the `/etc/systemd/system` directory and ensure the .sh scripts have the executable bit set.
5. Cross reference each of these files with the Challenge Artifacts section above and edit any lines, as needed
6. Run the following bash commands to complete system configuration:
```bash
-sudo systemctl start access-ssh.service`
-sudo systemctl enable access-ssh.service
-sudo systemctl start router-add-user.service
-sudo systemctl enable router-add-user.service
-sudo systemctl start router-add-web.service
-sudo systemctl enable router-add-web.service
-sudo systemctl start zulip-poster.service
-sudo systemctl enable zulip-poster.service
```

## Zulip Server Installation

1. Create an Ubuntu 22.04 LTS Server
2. Install [Zulip](https://zulip.readthedocs.io/en/latest/production/install.html) and create an organization `ACME` 
3. Create a a `collab` topic within the `general` stream
4. Create two bots with the following details. Take note of the User ID and API Key:
    - First Bot:
      - Name: `backup`
      - Email: `backup-bot@172.21.57.100`
    - Second Bot: 
      - Name: `intel`
      - Email: `intel-bot@172.21.57.100`
5. Assign the IPv4 address and default gateway according to the topology
6. Place the `startup-api.service` and `startup-api.sh` in the `/etc/systemd/system` directory and ensure the .sh script has the executable bit set
7. Cross reference each of these files with the Challenge Artifacts section above and edit any lines, as needed
