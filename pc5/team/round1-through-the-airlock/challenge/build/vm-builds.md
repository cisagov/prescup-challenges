# Unlinked VM Builds:

## app-server
  1. Set second network interface to bridge-net
  1. Boot the VM
  1. Run `sudo dhclient -i ens33`
  1. Run `wget <box url to API source bundle>` (see [here](https://stackoverflow.com/questions/46239248/how-to-download-a-file-from-box-using-wget))
  1. Rename the downloaded file to `api.zip`
  1. Run `mkdir api`
  1. Run `mv api.zip api`
  1. Run `cd api`
  1. Run `unzip api.zip`
  1. Install [Rustup](https://rustup.rs/)
  1. Install [sqlx-cli](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md#with-rust-toolchain)
  1. Update .env file in the API source bundle to `postgres://root:tartans@10.3.3.10:30432/c02api`
  1. In './migrations/20230412173932_starter_data.sql' change line 5
    - Change from: `INSERT INTO airlock_controls(id) VALUES ('cargo');`
    - Change to: `INSERT INTO airlock_controls(id, outer_open, inner_open) VALUES ('cargo', true, true);`
  1. Run `./scripts/up.sh`
  1. Run `cargo build --release`
  1. Shut down, save, remove bridge-net, restart
  1. Run `sudo firewall-cmd --add-port=3000/tcp --permanent`
  1. Run `sudo firewall-cmd --reload`
  1. Copy [api-server.service](./api-server.service) to `/etc/systemd/system` (or make a new file with the same contents)
  1. Run `sudo systemctl daemon-reload`
  1. Run `sudo systemctl enable api-server`
  1. Copy [start-challenge-api.sh](./start-challenge-api.sh) to `/home/user/api` (or make a new file with the same contents)
  1. Run `chmod +x ~/start-challenge-api.sh`
  1. Run `sudo systemctl stop api-server` to stop the server if it is running.
  1. Run `journalctl --rotate --vacuum-size=1` to clear logs.
  1. Press Ctrl-D to log out and log back in to save the command history to `~/.bash_history`
  1. Run `rm ~/.bash_history`
  1. Shut down, save, remove bridge-net
  1. Ensure that this VM IS visible to competitors.
  1. (Troubleshooting) If the database needs to be reset:
    - Run `sudo systemctl stop api-server`
    - Enter the `~/api` directory and run `./scripts/down.sh` followed by `./scripts/up.sh`
    - Run `sudo systemctl start api-server`
## ubuntu-server-2204-low-resource
  1. Set second network interface to bridge-net
  1. Boot the VM
  1. Run `sudo dhclient -i ens33`
  1. Run `wget <box url to client source bundle>` (see [here](https://stackoverflow.com/questions/46239248/how-to-download-a-file-from-box-using-wget))
  1. Rename the downloaded file to `client.zip`, run `mkdir client`, `mv client.zip client`, `cd client`, `unzip client.zip`
  1. Install [PyEnv](https://github.com/pyenv/pyenv) and follow the instructions after the installation to add it and `pyenv-virtualenv` to your .bashrc and .profile. Do not skip installing the Python build dependencies linked on the page (for Ubuntu)
  1. Log out and back in to be able to run pyenv
  1. Run `pyenv install 3.11.3`
  1. Run `pyenv global 3.11.3`
  1. Run `pyenv virtualenv client`
  1. Run `cd ~/client`
  1. Run `pyenv local client`
  1. Run `pip install -r requirements.txt`
  1. Copy [client-script.service](./client-script.service) to `/etc/systemd/system` (or make a new file with the same contents)
  1. Run `sudo systemctl daemon-reload`
  1. Run `sudo systemctl enable client-script`
  1. Open the `/etc/ssh/sshd_config` and add the line `PasswordAuthentication no` to the file.
  1. Shut down, save, change the second interface from bridge-net to check-net, restart
  1. Overwrite the file `/etc/netplan/00-installer-config.yaml` with [client-netplan.yaml](./client-netplan.yaml) (or update the existing contents to match)
  1. Run `sudo netplan apply`
  1. Edit `/etc/bash.bashrc` and comment out the line `/usr/sbin/script.sh`
  1. Wait until the challenge server's SSH key has been copied over before continuing to the next step
  1. Shut down and save
  1. Ensure that this VM is NOT visible.
## challenge-server
  1. Set the third network interface to check-net
  1. Boot the VM
  1. Copy the contents of `~/.ssh/id_rsa.pub` out of the VM to your clipboard and paste it into `~/.ssh/authorized_keys` on the `ubuntu-server-2204-low-resource` VM.
  1. Copy [challenge-server-check-net.nmconnection](./challenge-server-check-net.nmconnection) to `/etc/NetworkManager/system-connections` (or make a new file with the same contents)
  1. `sudo systemctl restart NetworkManager`
  1. Run `cd ~/challengeServer`
  1. Overwrite the file `~/challengeServer/config.yml` with [challenge-server-config.yml](./challenge-server-config.yml) (or update the existing contents to match)
  1. Copy [challenge-server-grading-script.py](./challenge-server-grading-script.py) to `~/challengeServer/custom_scripts` with the name `challengeGrading.py`
