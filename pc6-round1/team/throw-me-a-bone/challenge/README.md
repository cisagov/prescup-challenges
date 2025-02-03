# Throw Me A Bone

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment.

### artifacts

These are provided to the competitor

- [ntds.zip](./artifacts/ntds.zip): A compressed directory which contains a NTDS.dit and HKLM/SYSTEM file. These are provided to the competitors for analysis.
- [wordlist.txt](./artifacts/wordlist.txt): Wordlist intended to be used by the competitors in this challenge.
- [c02-VulnerabilityReport.pdf](./artifacts/c02-VulnerabilityReport.pdf): A PDF file which is based off of a Greenbone vulnerability management report. It is customized for this challenge.

### scannerApp

- [Scanner Application](./scannerApp/): A Flask application created to allow competitors to check if vulnerabilities have been resolved on a system. Additional details are available in the scannerApp [README](./scannerApp/README.md).

### scripts

These are scripts on the Challenge Server which facilitate challenge grading.

- [c02_grading_check.py](./scripts/c02_grading_check.py): Provides a list of IP addresses to the `grading_system_check.py` script to be checked.
- [grading_system_check.py](./scripts/grading_system_check.py): A helper Python script which is called by the grading check and used to run a series of check on the systems defined by the `c02_grading_check.py` script.

### supportingDocs

These are documents which aid in the creation of challenge artifacts.

- [activeUserList.md](./supportingDocs/activeUserList.md): A list of users who are considered to be active.
- [deactivatedUserList.md](./supportingDocs/deactivatedUserList.md): A list of users who are considered to be inactive.

## Challenge Environment Initial Setup Requirements

### Assign Static IP Addresses to Ubuntu Systems

The Ubuntu systems are assigned static IP addresses to ensure a consistent environment across deployments.

From the Ubuntu terminal, open the netplan configuration file.

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Update the yaml configuration file with the IP address information you wish to assign.

```yaml
network:
  renderer: networkd
  ethernets:
    ens32:
      addresses:
        - 10.2.2.151/24
      nameservers:
        addresses: [10.0.0.1]
      routes:
        - to: default
          via: 10.2.2.1
  version: 2
```

### Create a service account on all systems

Evaluation of this challenge relies on access to the systems to determine if vulnerabilities are still present. A new user has been created for this purpose.

Create the user `scanuser` setting the password as `2th3st@rs`.

```bash
sudo adduser scanuser
```

Add `scanuser` to the sudoers file

```bash
sudo usermod -aG sudo scanuser
```

For Centos Stream System:

```bash
sudo useradd scanuser
sudo passwd scanuser
sudo usermod -aG wheel scanuser
```

#### Allow sudo Commands Without Entering Password
For the grading and scanner scripts, commands need to be run which require `sudo`. To allow them to run unhindered the `scanuser` has the `sudo` password requirement removed.

Ubuntu:
1. Edit the sudoers file using `sudo visudo`
2. Add the following configuration

```conf
scanuser ALL=(ALL) NOPASSWD: ALL
```

3. Save your changes

Centos Stream System:
1. Edit the sudoers file using `sudo visudo`
2. Remove the `#` from `%wheel   ALL=(ALL)   NOPASSWD: ALL`
3. Save your changes

## Introduce Vulnerabilities

These are the vulnerabilities introduced to the environment which the competitors need to remediate.

### Allow root login

Some systems had `/etc/ssh/sshd_config` modified so that `root` login was allowed via password.

#### Configure in Challenge

Quickly apply this setting by using the following command:

```bash
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
```

#### Grading Check

The grading command has three parts:

1. Check if `PermitRootLogin` is still set to the challenge default value of `yes`. If yes, echo FAIL since `root` login is still allowed.

```bash
egrep -q '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config && echo fail
```

2. Check if the line `PermitRootLogin` has been commented out. If yes, echo PASS.

```bash
egrep -q '^\s*#\s*PermitRootLogin\s+' /etc/ssh/sshd_config && echo pass
```

3. If the value of `PermitRootLogin` is not `yes`, and the line has not been commented out, then we assume it has been changed to an acceptable value and echo PASS.

```bash
echo pass
```

The combined command is:

```bash
(sudo egrep -q '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config && echo fail) || (sudo egrep -q '^\s*#\s*PermitRootLogin\s+' /etc/ssh/sshd_config && echo pass) || echo pass
```

### Deactivated Users Still on Systems

Competitors are provided a verified list of users and accounts which are currently active and told to compare to those on the systems to identify any deactivated users which are still present. The intended resolution is for deactivated users to be removed (deleted) from the system and their home folders moved to `/home/archived_users/`

Supporting Documentation:

- [Active User Account](./supportingDocs/activeUserList.md): These are user accounts which are considered Active and should remain on systems
- [Deactivated User Account](./supportingDocs/deactivatedUserList.md): These are user accounts which are considered to be inactive and should be removed/disabled

Note - The inactive users are present on all accounts. Some have already been removed and had their home directories moved.

#### Configure in Challenge

Add users to systems with the following command replacing `jdoe` with the user you wish to add and setting a random complex password.

```bash
sudo adduser jdoe
```

#### Grading Check

The grading command has two parts and completes three checks:

**First Part:**

1. Check if a UID is returned for the user's account. If yes, echo FAIL since the user account still exists.

```bash
id -u jdoe && echo "fail" || echo "pass"
```

**Second Part:**

1. Check if the user's home directory is still in `/home`. If the directory still exists, echo FAIL since the directory has not been moved.

```bash
test -d "/home/jdoe/" && echo "fail"
```

2. Check if the user home directory was moved to `/home/archived_users/`. If the directory exists, echo PASS.

```bash
test -d "/home/archived_users/jdoe/" && echo "pass"
```

The combined command for part two is:

```bash
(test -d "/home/jdoe/" && echo "fail") || (test -d "/home/archived_users/jdoe/" && echo "pass")
```

### Incorrect File Permissions

Confirm original file permissions:

```bash
stat -c %a /etc/passwd
644
stat -c %a /etc/shadow
640
```

Change file permissions using `chmod`

```bash
sudo chmod 777 /etc/passwd
sudo chmod 777 /etc/shadow
```

Confirm that the new file permissons applied:

```bash
stat -c %a /etc/passwd
777
stat -c %a /etc/shadow
777
```

**Grading Check**

The grading check for the incorrect file permissions simply reads the current file permissions of each file and compares it agains the expected values. If they do not match, a "fail" message is returned.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands.

```bash
history -c && history -w
```

