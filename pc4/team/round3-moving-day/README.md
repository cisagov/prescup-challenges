# Moving Day

Exploit and manipulate a satellite system web API to gather data about the relocation of a Space Pirate moonbase.

**NICE Work Roles**
- [Cyber Operator](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-operator)
- [Data Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/data-analyst)
- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)

**NICE Tasks**
- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0266)- Perform penetration testing as required for new or updated applications.
- [T0342](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0342)- Analyze data sources to provide actionable recommendations.
- [T0618](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0618) - Conduct on-net activities to control and exfiltrate data from deployed technologies.
- [T0696](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0696)- Exploit network devices, security devices, and/or terminals or environments using various methods or tools.

## Background

Space pirates are known to be operating in our vicinity. They recently relocated their moonbase, and we are gathering any information we can about the new moonbase's strength.

We have limited information about the satellite system that the pirates use, but some data has been lost or corrupted. 

What we know:

- The Space Pirates are using an older model, deep space satellite system to send and receive data transmissions. This model satellite system includes a web service and an API. The specification regarding which ports these services use has been lost. 
- The satellite system has the IP address of `123.45.67.100`.
- This particular model of satellite is very sensitive, slow, and prone to failure when overloaded.
- The satellite system uses a web page to allow admins to download stored/relayed data; however, the specification regarding the storage page's location has been lost.

## Objectives

Your task is to collect additional data about the space pirates by utilizing their outdated satellite system. 

You will need to use the satellite system's web service and API to point the satellite at 3 different data relays in order to transmit the data that we need. Before you can retrieve the relayed data from the satellite system, you will have to find where the admin storage interface is on the website. 

After moving the satellite and collecting the packages from each of the three (3) relays, analyze the data to answer the questions below. 

Finally, disable the pirates' satellite system. 

## Getting Started

_Note: To play this challenge offline, please see the instructions in the [challenge directory](./challenge) ot get started._

DHCP provides valid addresses to both interfaces on your Kali systems. Run `sudo dhclient eth0` and/or `sudo dhclient eth1` to receive addresses on both interfaces before beginning your work.

Follow these steps to collect the data packages, analyze the data, and shut down the pirates' satellite system:

1. Visit `https://challenge.us/files` and read the provided satellite user manual.

2. Find the ports that are in use for the satellite system's website and API. Then, enumerate the website to find the admin storage interface.

3. Examine the satellite's web services and API  to determine how to point the satellite at each of the three (3) different data relays (coordinates are below). 

|Relay Name | Azimuth Coordinates | Elevation Coordinates |
|-----------|---------------------|-----------------------|
| Relay Gamma | -77 degrees 30 minutes 15 seconds | 164 degrees 47 minutes 30 seconds |
| Relay Omega | -83 degrees 22 minutes 07 seconds | 155 degrees 42 minutes 37 seconds |
| Relay Zed   | -73 degrees 33 minutes 23 seconds | 172 degrees 38 minutes 23 seconds |

4. Once the satellite's position is within one minute of the desired relay, you can access the satellite's storage page to retrieve the transmitted data package. 

5. Once you have collected information from at least one of the relays, you can begin analyzing the data to answer the Challenge Questions while retrieving other data. Use the provided data guides from `https://challenge.us/files` to help you analyze each data package.

6. Initiate the shutdown sequence on the satellite after retrieving all three data packages. Once  shutdown has been triggered, run the grading check found on: `https://challenge.us`.

## Challenge Questions

1. Enter the value of the storage-token, found by listing the files on the admin storage interface.  
2. Enter the value of the wa-token, found with the data recovered from the orbital weapons array (wa-data.zip)    
3. Enter the value of the sd-token, found with the data recovered from the moon base supply depot(sd-data.zip)  
4. Enter the value of the hq-token, found with the data recovered from the headquarters building (hq-data.zip)     
5. Using the data in wa-data.zip, what is the total battle complement of the weapons array as of the final report?  
6. Using the data in sd-data.zip, what is the total weight (in kilograms) of the final inventory stock plus shipping containers as of the final invoice date for the original supply depot? (number only, out to two decimal places)  
7. Using the data in hq-data.zip, what is the code name of the person who was in each room when each BOOM was heard?  
8. Enter the token awarded for successfully shutting down the satellite - visit https://challenge.us to retrieve this token.
