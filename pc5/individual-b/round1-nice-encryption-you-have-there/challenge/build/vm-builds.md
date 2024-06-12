# Unlinked VM Builds:

## challenge-server

1. Set first network interface to bridge-net
1. Boot the VM
1. Open a terminal window.
1. Run `sudo ./start-bridgenet.sh`.
1. Run `wget <box url to client source bundle>` (see [here](https://stackoverflow.com/questions/46239248/how-to-download-a-file-from-box-using-wget)).
1. Rename the downloaded file to `code.zip`.
1. Run `mkdir code`.
1. Run `mv code.zip code`.
1. Run `cd code`.
1. Run `unzip code.zip`.
1. Install [Rustup](https://rustup.rs/).
1. Run `sudo apt update && sudo apt install libssl-dev -y`.
1. Run `cargo build --release`.
1. Edit the `/home/user/challengeServer/config.yml` file.
1. Find the `hosted_files` section.
1. Change `enabled: false` to `enabled: true` under the `hosted_files` section.
1. Run `cp /home/user/code/target/release/client /home/user/challengeServer/hosted_files`.
1. Run `rm /home/user/challengeServer/hosted_files/example`.
1. Copy [code-server.service](./code-server.service) to `/etc/systemd/system`. (or make a new file with the same contents)
1. Run `sudo systemctl daemon-reload`.
1. Run `sudo systemctl enable code-server`.
1. Run `sudo /home/user/stop-bridgenet.sh`.
1. Shut down, save the VM, and ensure that it is not visible.
1. Switch the first network interface to competitor.
