# The Train Job

_Server Setup_

1. Download the challenge container images from [here](https://presidentscup.cisa.us/files/pc4/individualb-round2-the-train-job-largefiles.zip).
2. Install Docker and its command-line interface tool.
3. Unzip the downloaded file.
4. `sudo docker image load -i loader.tar`
5. `sudo docker image load -i train.tar`
6. Use the `start-containers.sh` and `stop-containers.sh` scripts to run the challenge (if you already use Docker for other things, be aware that `stop-containers.sh` runs the `docker network prune` command).
