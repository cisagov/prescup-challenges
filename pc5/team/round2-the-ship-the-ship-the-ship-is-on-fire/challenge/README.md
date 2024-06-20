# The Ship, The Ship, The Ship is on Fire

_Challenge Artifacts_

- can-bus-client
  - [can-bus-antenna-1.py](./can-bus-client/can-bus-antenna-1.py) and [can-bus-client-1.py](./can-bus-client/can-bus-client-1.py) send CAN Bus traffic over websockets to the can-bus-server. 

- can-bus-server
  - [protocol.py](./can-bus-server/protocol.py) - Used to modify the protocol.py file that is included with the can_remote python package. By default this code is installed here: `/home/user/.local/lib/python3.11/site-packages/can_remote/protocol.py`. Insert the code from this file after line 38 in `protocol.py`. When the correct message is discovered the `canbus_complete.txt` file is created. The grading script will check for the presence of `canbus_complete.txt` to determine that the correct data was sent to the server.

- gps-receiver
  - [UDPListener](./gps-receiver/UDPListener/) - .NET Core console application used to listen for UDP traffic sent from the gps-sender VM.  
  
  - [WebPortal](./gps-receiver/WebPortal/) - .NET Core web application used to monitor the GPS data sent from the `gps-sender` VM.  
 
- gps-sender
  - [gps-data.txt](./gps-sender/gps-data.txt) - Contains GPS coordinates sent to the `gps-receiver` by `gps-sender.sh`.
  - [gps-sender.sh](./gps-sender/gps-sender.sh) - Sends data from `gps-data.txt` to the `gps-receiver` VM. 

- modbus-client
  - [motorcontrolclient.py](./modbus-client/motorcontrolclient.py) - Python script that runs the Modbus client.

- modbus-server
  - [console_client.py](./modbus-server/console_client.py) - Modbus Python client that interacts with the Modbus server to control doors, smoke sensors and room temperatures.
  - [motorserver.py](./modbus-server/motorserver.py) - Modbus Python server that runs a motor controller server.
  - [spinningmotorclient.py](./modbus-server/spinningmotorclient.py) - Modbus client Python script that sets the state of the motor server's coils.
  - [statusconsoleserver.py](./modbus-server/statusconsoleserver.py) - Modbus server Python script that runs a Modbus status server.

- modbus-web
  - [ScadaWeb](./modbus-web/) - .NET Core web application used to monitor and view Modbus vales on the `modbus-server` VM.

- web-socket-client
  - [websocket-client2.py](./web-socket-client/websocket-client2.py) - Send websocket data to the `web-socket-server` VM.

- web-socket-server
  - [WebSocketServer2](./web-socket-server/) - .NET Core console application that receives websocket data from [websocket-client2.py](./web-socket-client/websocket-client2.py).


