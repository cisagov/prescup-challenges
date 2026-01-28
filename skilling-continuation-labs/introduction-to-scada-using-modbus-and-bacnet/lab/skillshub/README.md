# Skills Hub Artifacts

SCADA Web Application

[modbus-web](./modbus-web/) - Contains the C# source code for building the SCADA web application that communicates with the Modbus server. This web site is hosted on `10.7.7.10` in the lab.

SCADA Server 1

[garagedoor.py](./scada1-server/garagedoor.py) - Service to run to simulate Bacnet garagee door.

[theremometer.py](./scada1-server/thermometer.py) - Service to run to simulate temp control bacnet.

[alarm.py](./scada1-server/alarm.py) - Service to simulate bacnet alarm system.

[bacnetwrite.py](./scada1-server/bacnetwrite.py) - Writes bacnet values from the bacnet devices to a json file.

SCADA Server 2

[DeLorean Server](./scada2-server/delorean_server.py) - Modbus server running on port 502 on `10.3.3.56`.

[DeLorean Server Service](./scada2-server/delorean.service) - System service file to start the DeLorean Server.

[Reactor 1 Server](./scada2-server/reactor_server_1.py) - Modbus reactor server that runs on port 503 on `10.3.3.56`. Users don't interact with this service during the lab, but it will show up during nmap scans.

[Reactor 1 Server Service](./scada2-server/reactor1.service) - System service file to start the Reactor 1 Server.

[Reactor 2 Server](./scada2-server/reactor_server_2.py) - Modbus reactor server that runs on port 504 on `10.3.3.56`. Users don't interact with this service during the lab, but it will show up during nmap scans.

[Reactor 2 Server Service](./scada2-server/reactor2.service) - System service file to start the Reactor 2 Server.
