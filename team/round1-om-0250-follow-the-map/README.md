<img src="../../logo.png" height="250px">

# Follow the map
#### Category: Operate and Maintain
#### Difficulty Level: 250
#### Executive Order Category: Network Operations

## Background

Your network administrator has newly been hired and wants to know information about the network. There is an internal
network that consists of five different subnets that have numerous hosts. Multiple NMAP scans have been run and
condensed into five files, one to represent each individual subnet. The scans were unable to be saved chronologically
and have been saved with an NMAP extension which will limit what application you may use with them. Your admin has come
up with a couple of questions he wants answered that lie in the output of the NMAP scans.

## Getting Started

The answer to each question represents 1/4 of the flag.

1. Determine how many machines there are of the most common operating system throughout all of the subnets. _Note: Only
count machines that explicitly say "Linux" or "Windows" as their OS._
2. Which host in the entire network has the largest vulnerable surface area based on number of open ports?
3. How many machines explicitly state that they do not allow port 443 traffic?
4. Determine the number of hosts the specifically allow the Microsoft Windows RPC Service.

An example flag is formatted like this: `1,1.2.3.4,20,10`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.