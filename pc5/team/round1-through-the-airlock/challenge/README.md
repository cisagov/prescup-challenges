# Through the Airlock

_Challenge Artifacts_

- [api/](./api/) -- Source code directory for the controller system.
- [api-server.service](./build/api-server.service) -- Systemd unit file for starting the controller system.
- [start-challenge-api.sh](./build/start-challenge-api.sh) -- Called by `api-server.service` to set up the database before actually starting the controller system.
- [challenge-server-check-net.nmconnection](./build/challenge-server-check-net.nmconnection) -- (Spoiler) NetworkManager configuration for the grading network between the challenge server and the attacker VM.
- [challenge-server-config.yml](./build/challenge-server-config.yml) -- (Spoiler) The configuration for the challenge server.
- [challenge-server-grading-script.py](./build/challenge-server-grading-script.py) -- (Spoiler) The script being run when clicking the "Grade Challenge" button on the challenge server.
- [client-netplan.yaml](./build/client-netplan.yaml) -- (Spoiler) The netplan file used to configure the attacker system's networks.
- [client-script.service](./build/client-script.service) -- (Spoiler) Systemd unit file for starting the attack script on the rogue system.
- [client/](./client/) -- (Spoiler) Source code for the script that is attacking the controller system.
- [vm-builds.md](./build/vm-builds.md) -- (Spoiler) Instructions for configuring the challenge VMs as needed for this challenge.
