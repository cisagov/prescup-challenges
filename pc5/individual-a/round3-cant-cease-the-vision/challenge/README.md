# Can't Cease The Vision
_Challenge Artifacts_

Hosted Environment
These artifacts are placed on the indicated machines within the hosted environment. They produce the live network traffic examined by competitors. They will not operate as intended unless run in an environment which mirrors the hosted challenge. 

- These artifacts are placed on the [vision-camera](./hostedEnvironment/vision-camera.tar.gz) machine.
    - `create-challenge.service`: Runs the `main.sh` script and always restarts the service, if needed.
    - `main.sh`: Takes the infinity variable and creates 6 video feeds with braille data hidden in feed(1-6).mp4.
    - `sender[1-6].py`: Sends feed(1-6).mp4 over UDP

- These artifacts are placed on the [vision-camera-viewer](./hostedEnvironment/vision-camera-viewer.tar.gz) machine.
    - `8XXX-request.service`: Constantly browse to vision-camera1 over ports 8000, 8008, 8080, 8088, and 8888.

- These artifacts are placed on the [vision-camera1](./hostedEnvironment/vision-camera1.tar.gz) machine. 
    - `senderX.service`: Executes senderX.sh
    - `senderX.sh`: Listens on ports 8000, 8008, 8080, 8088, and 8888 and streams an authorized dam.mp4.

Standalone Environment
- sensoroni_securityonion_cctv.pcap -- A packet capture taken within the hosted environment capturing the network traffic to be examined. 

## ⚠️ Large Files ⚠️
This challenge includes large files as a separate download. Please download the large files [here](). The packet capture file extracted from the large file zip was captured in the hosted environment. It allows this challenge to be completed outside of the hosted environment. The zipped file is ~224 MBs and the extracted file is ~317 MBs.