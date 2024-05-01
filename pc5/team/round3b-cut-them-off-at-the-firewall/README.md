# Cut Them Off At The Firewall

There is a threat of exfiltration using port `1337`.  Block port `1337` on the router.

**NICE Work Role**

- [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/network-operations-specialist)

**NICE Task**

- [T0035](https://niccs.cisa.gov/workforce-development/nice-framework/): Configure and optimize network hubs, routers, and switches

## Background

You must create a firewall rule that allows required traffic and blocks other traffic.

## Getting Started

Create a firewall rule on the pfSense firewall at `10.200.200.1` to block port `1337`. A  website is running on port `1337` at `10.10.10.100` that can be used to test the rule. Other traffic must be allowed to pass. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|cut-them-off-kali|user|tartans|
|pfsense|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.200.200.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. Is port 1337 successfully blocked on 10.10.10.100?