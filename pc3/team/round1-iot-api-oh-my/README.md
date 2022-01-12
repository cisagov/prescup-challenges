
# IoT API? Oh my.

Given a packet capture, you must determine how to interact with an IoT Cloud API to force devices into a desired state.


**NICE Work Roles:**   

[Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

[Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)


**NICE Tasks:**

- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0591&description=All) - Perform analysis for target infrastructure exploitation activities.
- [T0694](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0695&description=All) - Examine intercept-related metadata and content with an understanding of targeting significance.


## Background  

You are given a packet capture that shows an IoT device hub interacting with the hub's cloud API. Analyze the packet capture to determine: 
1. The IP address and port of the IoT API
2. The commands that the API supports
3. How to control IoT device state via the API

You will need to use the API to control the state of two (2) IoT devices connected to the hub after receiving a valid API key. You must unlock a door and power off a camera.


## Getting Started

Start the API server that is included in the challenge directory by running the command:

```
python3 app-server.py 0.0.0.0 12345
```

After the API server is running, you can proceed with the challenge by interacting with the server. 

Open the packet capture that is provided and determine how to interact with the API. 

You are tasked to do the following by interacting with the API:
1.  Authenticate to the API server and receive an API key
2.  Unlock the door via the API
3.  Power off the camera via the API

To check your progress, use the grading script included in this directory by running the command:

```
python3 gradingScript.py
```
