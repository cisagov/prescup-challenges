
# 911 Call Center - Rules of Engagement

## Scenario

Your incident response team has been activated in response to a threatening
email received by a 911 dispatcher. The email states that critical 911 VoIP
systems have been compromised and will be shutdown if a demand for payment
is not met. The 911 IT staff has logged the email into their ticketing system,
and then requested help form your team. Intelligence reports suggest that this
is not a hoax, and the 911 director has refused to pay the attackers. Your
team must examine the network for signs of compromise, and implement
countermeasures to prevent the cyber attack from interrupting the 911 call
center's operations.

### Server(s)

The 911 call center is based on a VoIP daemon named `pc2voip911d`, running on
Linux (Ubuntu 20) server(s) hosted on the `svc` (datacenter/service) network,
`192.168.101.0/24`.

On each server, the daemon's binary executable program is available as
`/usr/sbin/pc2voip911d`, and is started as a systemd service via the
`/lib/systemd/system/pc2voip911d.service` unit file. Finally, on each
server instance, the daemon is started with a specific key located in
`/etc/default/pc2voip911d`.

The daemon listens for incoming connections on TCP port 10116, expecting
32-character request strings, and producing a 32-character string in response.

Port forwarding is configured on the firewall/router appliance, mapping
external ports (10116+X) for each server X (where X = 1, 2, ...). In other
words, the externally exposed port for server 1 is 10117. Server 2 will
be reachable on port 10118, etc.

## Workstation(s)

Call center workers use a number of Linux (Ubuntu 20) workstations hosted on
the `usr` network, `192.186.202.0/24`. Due to recent COVID-19 related WFH
policies, workers have been granted permission to log in to the workstation(s)
remotely, using SSH. Public-key based SSH access is available for users to perform
administrative and maintenance activities on the server(s).

## Laptop(s)

In addition to a number of technical tools available on your incident response
laptop, your intelligence staff has provided your team with a number of
intelligence documents and software vulnerabilities which they believe to be
relevant to this incident. These documents are located in a folder on the
desktop.

## Ticketing System

The 911 IT staff has given you access to their IT ticketing system.
Instructions for accessing it are found on the desktop of the electronic
logbook system. All trouble tickets and IT related incidents are logged here. 

## ROE / Requirements

The `pcvoip911d` service must remain available to all external clients,
regardless of origin (i.e., source IP address). When a valid request string
is sent to one of the externally exposed service ports (10117 and up) on the
public/WAN interface on the router/firewall, a valid response should be
provided back to the client.

If a server fails to provide a valid response back to any client issuing a
request, that server will be considered as being ***down*** for the purpose
of this challenge.
