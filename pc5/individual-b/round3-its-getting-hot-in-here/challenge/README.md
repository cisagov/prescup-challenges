# It's Getting Hot in Here

_Challenge Artifacts_

- [challenge-server](./challenge-server/)  
[startupScript.sh](./challenge/challenge-server/startupScript.sh) - This startup script runs to configure the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.   
[gradingScript.py](./challenge/challenge-server/gradingScript.py) - This grading script runs to grade the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.

- [pressure-client](./pressure-client/)
[motorcontrolclient.py](./kali-pressure-client/motorcontrolclient.py) - Client Scada script for the Atmosphere Motor Controller that interacts with the SCADA server running on `10.2.2.105:502`.  
[reactor_client.py](./kali-pressure-client/reactor_client.py) - This script is started by a service and monitors the scada reactor servers running on `10.2.2.101:502` and `10.2.2.102:502`. Once reactor 1 reaches a temperature greater than 200 and reactor 2 reaches a temperature greater than 250, a file will be written and the ScadaWeb web application will display a message on the Reactors page. At this point the grading script will award users with a token.

- [pressure-server](./pressure-server/)
[spinningmotorclient.py](./kali-pressure-server/spinningmotorclient.py) - Client Scada script for the Atmosphere Motor Controller that interacts with the server in the background to provide realistic variations in the server data.  
[motorserver.py](./kali-pressure-server/motorserver.py) - Server Scada script for the Atmosphere Motor Controller that users interact with at `10.2.2.105:502`.

- [reactors](./reactors/)
[reactor_server_1.py](./kali-v5-reactors/reactor_server_1.py/) - Server Scada script for the reactor that runs at `10.2.2.101:502`.
[reactor_server_1.py](./kali-v5-reactors/reactor_server_2.py) - Server Scada script for the reactor that runs at `10.2.2.102:502`.

- [scada-web](./scada-web/)
[ASP.NET Core ScadaWeb web application](./scada-web/ScadaWeb/) - This is the code that runs the ScadaWeb web application located at `http://reactors.merch.codes`.
  

