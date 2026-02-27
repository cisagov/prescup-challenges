# The Italian Job

*Challenge Artifacts*

This README file contains details on how the challenge was created. 

### camera

Contains the files for the simulated ONVIF-compliant camera.

- [app](./camera/app): Contains the Flask app that simulates the camera.
  - [images](./camera/app/images/): A collection of images of an office made in Blender used by the camera
  - [app.py](./camera/app/app.py): The Flask app containing the various routes for the camera
- [Dockerfile](./camera/Dockerfile): The Docker file for the camera.
- [entrypoint.sh](./camera/entrypoint.sh): The entrypoint script used by the `Dockerfile`. Updates `ip route` and runs the Flask app

### gateway

Contains the files for a gateway allowing traffic from the TMC or cabinet to the Kali box, but not the other direction.

- [Dockerfile](./gateway/Dockerfile): The Docker file for the gateway.
- [gateway.sh](./gateway/gateway.sh): The entrypoint script used by the `Dockerfile`. Sets up the rules in `iptables` and runs `tcpdump` for logging

### logReader and logReaderCompetitor

Runs a Python script that monitors for files on `/mnt/usb` for processing with a vulnerable version of `exiftools`. These containers are combined, as they are almost identical; any differences are called out below. The competitor device is accessible to the competitor via SSH.

- [imgs](./logReaderCompetitor/imgs): Contains some example images so the competitor can see how the script runs. Only on competitor
- [logs](./logReaderCompetitor/logs): Contains some example logs so the competitor can see how the script runs. Only on competitor
- [Dockerfile](./logReaderCompetitor/Dockerfile): The Docker file to build the host.
- [entrypoint.sh](./logReaderCompetitor/entrypoint.sh): The entrypoint script used by the `Dockerfile`. The non-competitor version sets up the token and routing.
- [exif.sh](./logReaderCompetitor/exif.sh): Not available on the container, used manually before building; a helper script I used to write all the exif data for the example images
- [exiftool-12.20.tar.gz](./logReaderCompetitor/exiftool-12.20.tar.gz): A copy of the vulnerable version of `exiftool`
- [generate_timing_logs.py](./logReaderCompetitor/generate_timing_logs.py): Not available on the container, used manually before building; a helper script I used to write all the logging data to match the images exif data
- [ingest.py](./logReaderCompetitor/ingest.py): The image/log processing script; the non-competitor version runs `exiftool` with `strace` so the exploit can be logged
- [supervisord.conf](./logReaderCompetitor/supervisord.conf): The `supervisord` configuration that runs the `ingest.py` script (and ssh on the competitor machine).

### trafficController

Contains the files for the simulated traffic controller web panel.

- [app](./trafficController/app): Contains the Flask app that simulates the traffic controller web panel.
  - [static](./trafficController/app/static/): Contains CSS for the web panel
  - [templates](./trafficController/app/templates/): Contains the HTML templates used by Flask
  - [app.py](./trafficController/app/app.py): The Flask app containing the various routes for the traffic controller
  - [panel.py](./trafficController/app/panel.py): Contains the code and data that controls the traffic controller panel
  - [simulator.py](./trafficController/app/simulator.py): Contains the code that simulates the traffic signals changing
- [Dockerfile](./trafficController/Dockerfile): The Docker file for the traffic controller.

### trafficSwitch

Contains the files for the "network switch" device that grants access to the traffic cabinet

- [Dockerfile](./trafficSwitch/Dockerfile): The Docker file for the traffic switch.
- [entrypoint.sh](./trafficSwitch/entrypoint.sh): The entrypoint script used by the `Dockerfile`. Sets up routing and the tokens
- [grader_key.pub](./trafficSwitch/grader_key.pub): The public key used by the grader device to load the users "USB" onto the device
- [supervisord.conf](./trafficSwitch/supervisord.conf): The `supervisord` configuration that runs the `updater.py` script and `sshd`
- [updater.py](./trafficSwitch/updater.py): Python script that monitors `/mnt/usb` for an `update.tcu` file; runs the bash scripts inside

### updateStation

Contains the files for the workstation the user breaks into to tamper with the update files

- [updateFiles](./updateStation/updateFiles/): Contains the various files that are zipped up to create the `update.tcu` file
  - [build_tcu.py](./updateStation/updateFiles/build_tcu.py): Not included in the running container; used during build time to create the `update.tcu` file using the other files in this directory
- [Dockerfile](./updateStation/Dockerfile): The Docker file for the workstation.
- [entrypoint.sh](./updateStation/entrypoint.sh): The entrypoint script used by the `Dockerfile`. Sets up routing and the tokens
- [grader_key.pub](./updateStation/grader_key.pub): The public key used by the grader device to load the users "USB" onto the device

## Challenge Environment Initial Setup Requirements 

This challenge is run entirely using Docker and Docker compose, so start up is very straightforward.

### Installing Docker

First, install Docker and Docker compose, using the official docker instructions for whichever operating system you are using. The entire challenge can then be launched easily using 

`docker compose up -d`

TODO: Add any details about getting in? Maybe VNC?

### Grading

This challenge does involve grading.

TODO: Grading details? Need to figure out to do with it