# The Crucible

*Challenge Artifacts*

This README file contains details on how the challenge was created and how it could be recreated in a different environment. 

### champion

This server simply holds a token in the home directory; the catch is the competitor must repair a corrupted private key to gain access. This directory contains the scripts to create/corrupt the key, as well as the private key used in the competition. 

- [corrupted](./champion/corrupted/): Contains the corrupted SSH keys as generated using the `generate_keys.sh` script.
  - [id_rsa](./champion/corrupted/id_rsa): The corrupted private key
  - [id_rsa.pub](./champion/corrupted/id_rsa.pub):
- [original](./champion/original/): Contains the original SSH keys as generated using the `generate_keys.sh` script.
  - [id_rsa](./champion/original/id_rsa): The original private key
  - [id_rsa.pub](./champion/original/id_rsa.pub): The original public key
- [generate_keys.sh](./champion/generate_keys.sh): A `Bash` script that generates a new key pair and removes the `modulus` fields from the private key. Execute as `./generate_key.sh {original_dir} {corrupted_dir}`

### honor

This server hosts a web directory listing with `nginx` and uses Docker to run a `Python` script that checks `PINs` entered on port `61234`.

- [public](./honor/public/): The directory made public by the `nginx` container. Initially, only contains the `oblivion.jpg` file; the `id_rsa` file and `token.txt` file are moved into this directory when the correct `PIN` is provided.
  - [oblivion.jpg](./honor/public/oblivion.jpg): An image of a blackhole used to hide `protocol.txt` as provided to competitors (that is, `steghide` has already been used on it). The original image can be found at [https://news.uchicago.edu/sites/default/files/images/2022-10/sgr%20A%2A%20ESO%20and%20M.%20Kornmesser%20690.jpg](https://news.uchicago.edu/sites/default/files/images/2022-10/sgr%20A%2A%20ESO%20and%20M.%20Kornmesser%20690.jpg)
- [src](./honor/src/): Contains the source code and other files that are placed inside the docker container running the `Python` script. 
  - [config.py](./honor/src/config.py): A `Python` script that loads a few values used by the `server.py` script.
  - [id_rsa](./honor/src/id_rsa): This is the same corrupted private key found on the [champion server](#champion).
  - [server.py](./honor/src/server.py): The `Python` script that checks `PINs` entered on port `61234`.
  - [token.txt](./honor/src/token.txt): The start-up script places the actual Token value in this file. 
- [docker-compose.yaml](./honor/docker-compose.yaml): The Docker compose script used to build and run both Docker containers
- [nginx.conf](./honor/nginx.conf): The configuration file used by the `nginx` Docker container; simply enables a web directory listing of the `/public` directory in the container
- [protocol.txt](./honor/protocol.txt): Hidden using `steghide` in `oblivion.jpg`; provides necessary hints to decipher the encryption algorithm used by `phantom.us` and `oblivion.us`

### oblivion

This server hosts a Docker container that listens for incoming UDP packets on port `1337`. Packets are encrypted; the competitor must perform an `arpspoof` attack to eavesdrop on them.

- [src](./oblivion/src/): This directory contains the scripts and other files shared with Docker container
  - [config.py](./oblivion/src/config.py): A `Python` script that loads a few values used by the `server.py` script.
  - [encryptor.py](./oblivion/src/encryptor.py): A `Python` script that implements the encryption and decryption functions needed by the server.
  - [publickey.txt](./oblivion/src/publickey.txt): This is the same public key found on the [champion server](#champion).
  - [server.py](./oblivion/src/server.py): The `Python` script that listens for incoming `UDP` packets.
  - [token.txt](./oblivion/src/token.txt): The start-up script places the actual Token value in this file. 
- [docker-compose.yaml](./oblivion/docker-compose.yaml): The Docker compose script used to build and run the Docker container
- [Dockerfile](./oblivion/Dockerfile): Builds the Docker container and installs `ping` and `arp` inside it

### phantom

This server hosts a Docker container that sends encrypted UDP packets to `oblivion.us` on port `1337`. The competitor must perform an `arpspoof` attack to eavesdrop on them.

- [src](./phantom/src/): This directory contains the scripts and other files shared with Docker container
  - [config.py](./phantom/src/config.py): A `Python` script that loads a few values used by the `victim.py` script.
  - [encryptor.py](./phantom/src/encryptor.py): A `Python` script that implements the encryption and decryption functions needed by the `Python` script.
  - [publickey.txt](./phantom/src/publickey.txt): This is the same public key found on the [champion server](#champion).
  - [victim.py](./phantom/src/victim.py): The `Python` script that sends encrypted `UDP` packets.
  - [token.txt](./phantom/src/token.txt): The start-up script places the actual Token value in this file. 
- [docker-compose.yaml](./phantom/docker-compose.yaml): The Docker compose script used to build and run the Docker container
- [Dockerfile](./phantom/Dockerfile): Builds the Docker container and installs `ping` and `arp` inside it

### scripts

These are various scripts or files used during setup or grading.

- [start.py](./scripts/start.py): The start up script used by `challenge.us`. Places tokens and installs `steghide` on the Kali machine.

## Challenge Environment Initial Setup Requirements 

The setup generally requires installing Docker on the various servers, then using `docker compose`. However, `champion.us` will require us to configure `SSH`.

### Champion

First, make sure `ssh` is installed, and enable it.

```bash
sudo apt install openssh-server openssh-
sudo systemctl enable ssh
sudo service ssh start
```

Now we need to place the public key in the `authorized_keys` file and disable using passwords with `SSH`. Assuming you have placed the `id_rsa.pub` file in the home directory of `champion.us`, you can do this with the following command:

```bash
mkdir ~/.ssh
cat id_rsa.pub >> ~/.ssh/authorized_keys
```

To disable SSH, we need to uncomment and set `PasswordAuthentication` to `no` in `/etc/ssh/sshd_config`. You can do this manually, or with the following [commands](https://superuser.com/a/1486297).

```bash
sudo sed -E -i 's|^#?(PasswordAuthentication)\s.*|\1 no|' /etc/ssh/sshd_config
if ! grep '^PasswordAuthentication\s' /etc/ssh/sshd_config; then echo 'PasswordAuthentication no' |sudo tee -a /etc/ssh/sshd_config; fi
```

Now restart `sshd`, and this server should be ready to go.

```bash
sudo service ssh restart
```

### Honor, Oblivion, and Phantom

This servers all use `docker compose`, and thus require little manual set up. First, install Docker as described in the [documentation](https://docs.docker.com/engine/install/ubuntu/):

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

Now log out, and log back in to reset your permissions.

If you haven't already, load all of the files for the server you are setting up into the home directory of the server. Now, run the following command to build and start the container(s).

```bash
docker compose build && docker compose up -d
```

The challenges should now be running and will restart automatically when the server is rebooted.

### Grading

No grading! All tokens are discovered directly.

## Cover Tracks

Prior to saving the server templates, clear the history to prevent competitors from reviewing any previously run commands. 
 
```bash
history -c && history -w
```

Be sure to change any passwords, or configure them to disallow SSH with a password.
