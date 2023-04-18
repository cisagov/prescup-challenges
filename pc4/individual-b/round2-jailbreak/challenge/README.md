# Jailbreak

_Server Setup_

1. Download the challenge container image from [here](https://presidentscup.cisa.gov/files/pc4/individualb-round2-jailbreak-largefiles.tar.gz).
2. Install Docker and its command-line interface tool.
3. `sudo docker image pull mongo`
4. `sudo docker image load -i individualb-round2-jailbreak-largefiles.zip`
5. Use the `start-containers.sh` and `stop-containers.sh` scripts to run the challenge (if you already use Docker for other things, be aware that `stop-containers.sh` runs the `docker network prune` and `docker volume prune` commands).

Note that for challenge question 2, you will need to reach the path of the `flag2.txt` file in this directory instead of `/root/flag2.txt` (or you can move it to `/root/flag2.txt` if you prefer).
