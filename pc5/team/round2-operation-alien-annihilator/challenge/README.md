# Operation Alien Annihilator

_Challenge Artifacts_

- [ManagementPortal](./ManagementPortal) - Contains the source code for the ManagementPortal web site that users interact with for questions 1 and 2. Also contains MongoDB statements to add users and inventory items. This .NET 6.0 code can be compiled and published with the following commands:

```bash
dotnet build --configuration Release
dotnet publish --configuration Release
```

- [webapp-api](./webapp-api/) - Static web site files that competitors must access through calls from the webapp-mongo-db server.

- [sensor-api/sensor.py](./sensor-api/sensor.py) - File that starts up external-facing sensor API that users must send POST requests through to update settings on server sensors.
- [sensor-api/send_msg.sh](./sensor-api/send_msg.sh) - Loops sending message to `wan-user` about firewall getting its password updated. 
- [sensor/sensor.py](./sensor/sensor.py) - File that starts up internal sensor API that takes requests from `sensor-api` and applies updates to server sensors.
- website/[website.py](./website/website.py) - File that starts up website that handles storing files for users. Authentication is done by referencing Mattermost API.
- [website/insert_file.py](./website/insert_file.py) - File that is used during startup to insert target file into website database.
- [wan-user/sensor_update.py](./wan-user/sensor_update.py) - Script that loops and sends updates to `sensor-api` to ensure that server sensors have the correct settings and servers aren't overheating.
