# Hide and Seek

Perform file system forensics.

**NICE Work Roles** 

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/cyber-defense-forensics-analyst) 

**NICE Tasks**

- [T0532](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0532) - Review forensic images and other data sources (e.g., volatile data) for recovery of potentially relevant information.

- [T0286](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0286) - Perform file system forensic analysis.

### NOTICE
The Windows VM for this challenge has an activation issue. In the event it shuts down, you can power it back on via the Gamespace console viewer.

## Background

The food items aboard the ship are not labeled properly. The labels only show food item GUIDs. XeNO is behind this misdeed. They are asking to abandon the mission in exchange for the mapping between the GUIDs and the food items. They have also mentioned that some of the food containers aboard the ship are poisoned. 

## Getting Started

We have found a USB drive lying on the floor of XeNO's office space and believe that it might contain the mapping we are looking for. The USB drive has been forensically imaged and the image is available for your analysis. It is attached as an iso to the `analyst` VM. 

Your end goal is to analyze the forensic image and find the GUID - food item mapping.

## Challenge Questions

1. What item corresponds to 267f75b7-222c-47f2-ac9d-8f0a7eb8058c? It is stored next to backup volume boot record.
2. What item corresponds to 49292006-a997-4cee-89b8-28a868c31267? It is stored in the slack space of deleted pdf file present on the USB.
3. What item corresponds to c8dea1c0-faba-4aaf-8aae-fc11ea68cbc3? It is stored in a file located at the beginning of the 11th unallocated cluster on the image. The file size is 27506 bytes. The file might be  missing file footer/trailer. 
