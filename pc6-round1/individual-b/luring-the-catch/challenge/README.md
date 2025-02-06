# Luring the Catch

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment.

## Challenge Server

- [Fake Fish Company Website](./fakeFishWebsite/): A single page HTML website run by Flask on the Challenge Server

- Grading Scripts: The [GetMessages.py](./getMessages.py) script evaluates the phishing email sent by the competitor. It verifies the email was sent to the correct recipient and that the URL points to `lure.fakefish.co`. When those criteria are met, it passes the masked URL to the [connectAndExecute.py](./connectAndExecute.py) script. This script connects to the `workstation` virtual machine, uses the URL to download the competitor crafted file, makes the file executable, and then runs it. The script has a mechanism to check for previous attempts and will kill any running processes and cleanup previous files before downloading and running a new file.

## MailCatcher

MailCatcher is a simple SMTP server which "catches" any messages sent to it. Those messages are then displayed in a web interface.

Reference: https://github.com/sj26/mailcatcher
License: https://github.com/sj26/mailcatcher/blob/main/LICENSE

### Install MailCatcher

In the Challenge Environment, MailCatcher has been installed on a Kali system. Outside of the Challenge Environment it can be installed on the Operating System of your choice adjusting the installation process as necessary.

#### On the Kali System

```bash
sudo gem install mailcatcher
```

### Assign a static IP

- Address: 10.2.2.151
- Netmask: 255.255.255.0
- Gateway: 10.2.2.1
- DNS Server: 10.0.0.1

### Create a Cron Job

Since MailCatcher runs as a Daemon, a Cron Job is used to start it when the Kali system boots.

`sudo crontab -e`

```text
@reboot /usr/local/bin/mailcatcher --ip 10.2.2.151 --smtp-port 25 --http-port 1080
```

### Supporting Changes on Challenge Environment pfSense

Host Override:
`mail.fakefish.co 10.2.2.151`

Custom Options:

```text
server:
local-zone: "fakefish.co." static
local-data: "fakefish.co. IN MX 10 mail.fakefish.co."
local-data-ptr: "10.2.2.151 mail.fakefish.co."
```

### Supporting Changes on Challenge Environment k3s Server

The Challenge Environment includes a preconfigured Mail service on the `merch.codes` domain. We want a user in this domain to be able to send email to an email address in the `fakefish.co` domain. The following change needs to be completed to allow email to send outside of the `merch.codes` domain.

`sudo nano /home/user/default/appdata/postfix-conf/main.cf`
Locate `default_transport` and comment this out.

## MinIO Server

MinIO is an object store which provides S3 compatible storage.

Reference: https://min.io/docs/minio/linux/operations/install-deploy-manage/deploy-minio-single-node-single-drive.html#minio-snsd
License: https://min.io/compliance

### Install MinIO

In the Challenge environment, MinIO has been installed on an ubuntu 22.04.04 system.

#### Update the Ubuntu Server

```bash
sudp apt update
sudo apt upgrade
sudo apt auto-remote
sudo apt clean
```

#### Download and install MinIO

```bash
wget https://dl.min.io/server/minio/release/linux-amd64/archive/minio_20240803043323.0.0_amd64.deb -O minio.deb
sudo dpkg -i minio.deb
```

#### Make a directory to contain the data

`sudo mkdir /mnt/minio-data`

#### Create a user for MinIO

```bash
sudo groupadd -r minio-user
sudo useradd -M -r -g minio-user minio-user
sudo chown minio-user:minio-user /mnt/minio-data
```

#### Create a MinIO configuration file

`sudo nano /etc/default/minio`

```conf
# MINIO_ROOT_USER and MINIO_ROOT_PASSWORD sets the root account for the MinIO server.
# This user has unrestricted permissions to perform S3 and administrative API operations on any resource in the deployment.
# Omit to use the default values 'minioadmin:minioadmin'.
# MinIO recommends setting non-default values as a best practice, regardless of environment

MINIO_ROOT_USER=myminioadmin
MINIO_ROOT_PASSWORD=m1nio@dmin

# MINIO_VOLUMES sets the storage volume or path to use for the MinIO server.

MINIO_VOLUMES="/mnt/minio-data"

# MINIO_OPTS sets any additional commandline options to pass to the MinIO server.
# For example, `--console-address :9001` sets the MinIO Console listen port
MINIO_OPTS="--console-address :9001"

minio server --certs-dir /opt/minio/certs

MINIO_BROWSER_REDIRECT_URL=https://s3.merch.codes

MINIO_DOMAIN=api.merch.codes
```

#### Enable the MinIO Service

`sudo systemctl enable minio.service`


## Update the IP address of the Ubuntu server

Note: This step was done last due to configurations in the Challenge environment. It can be done earlier if you are building a system from scratch.

```yaml
network:
  renderer: networkd
  ethernets:
    ens32:
      addresses:
        - 10.1.1.151/24
      nameservers:
        addresses: [10.0.0.1]
      routes:
        - to: default
          via: 10.1.1.1
  version: 2
```

### Add TLS Certificates to MinIO

Create a directory for the certs and add appropriate certificates

```bash
sudo mkdir /opt/minio/certs
cd /opt/minio/certs
sudo mkdir api-merch.codes
sudo nano private.key # Copy 'merch-codes-key.pem certificate from Challenge Server'
sudo nano public.crt # Copy 'merch-codes.pem' certificate from Challenge Server'
sudo mkdir api-merch.codes
cd api-merch.codes
sudo nano private.key # Copy contents of 'api-merch-codes.key'
sudo nano public.crt # Copy certificate from 'api-merch-codes.crt'
sudo chown minio-user:minio-user /opt/minio/certs
```

### Create a user in Minio GUI

This will be used by the competitors to access MinIO since self-registration is not currently supported.

- Username: user
- Password: tartans@1
- Permissions: readwrite