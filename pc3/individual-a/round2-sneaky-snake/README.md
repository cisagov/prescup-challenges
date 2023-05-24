
  # Sneaky Snake

Some files have been recently updated, including a script used internally for your company. Upon executing it, an employee reported some weird events occurring and has requested for someone to take a look at their machine. You must analyze the script and its associated files to determine what's happening and the root cause of the malicious behavior.

  **NICE Work Roles:**   

  - [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

  - [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)


  **NICE Tasks:**

  - [T0036](https://niccs.cisa.gov/workforce-development/nice-framework) - Confirm what is known about an intrusion and discover new information, if possible, after identifying intrusion via dynamic analysis.
  - [T0400](https://niccs.cisa.gov/workforce-development/nice-framework) - Correlate incident data and perform cyber defense reporting.
  - [T0258](https://niccs.cisa.gov/workforce-development/nice-framework) - Provide timely detection, identification, and alerting of possible attacks/intrusions, anomalous activities, and misuse activities and distinguish these incidents and events from benign activities.
  - [T0166](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform event correlation using information gathered from a variety of sources within the enterprise to gain situational awareness and determine the effectiveness of an observed attack.


  ## Setting Up
  
  ***Note: Setting up this challenge will invoke malicious actions on your machine. Please ensure you create a VM just for this challenge and do not connect the VM to the internet.** 
  
  Before beginning this challenge, you will need to make sure to put the folder **"round2-sneaky-snake"** on your VM's desktop for this challenge to run properly. Once that folder is on your desktop, go ahead and follow the next steps to finish setting up this challenge: 
  
  - Navigate to the [challenge](challenge) directory and change access permissions to the [install.sh](challenge/install.sh) shell script to make it executable. You can do this by writing the command below on your VM's terminal: 
  ```
   chmod +x install.sh
   ```

   - Once the [install.sh](challenge/install.sh) shell script has the right access permissions, you can go ahead and execute it with the following command:
  
   ```
   ./install.sh
   ```
   - This is going to prompt you for your VM's password and, once entered, it will reboot your VM in order to apply important factors needed to achieve this challenge. 
   
   - ***Note: The [install.sh](challenge/install.sh) shell script was not provided in the actual competition, instead, it is going to be used just once to set up your environment for this challenge. Seeing the contents written inside the [install.sh](challenge/install.sh) shell script will spoil the answers for this challenge, so it is best to avoid interacting with the [install.sh](challenge/install.sh) shell script aside from the commands mentioned before.** 

   - Once your VM reboots, you are good to begin this challenge. 

  ## Background

  Your organization has recently updated an internal script used to track machines and detect intrusions.  The script runs a variety of commands on the users' machine, records the results to a local CSV file, and send those same results to an API for admins to review.

  Upon downloading and executing the new version, an employee noted that it ended up logging them out of their machine. The employee states that they also recently updated Python by using instructions found online. IT is unsure about the validity of the instructions the user found. At this time, we are unsure if the issue is with our new script or with something on the user's Kali machine. 

  You have been tasked to look at the upload script and the user's python environment to determine the cause of this abnormal behavior. 

  ## Getting Started

  In the challenge directory is a file called [upload.py](challenge/upload.py), along with the users [CSV output](challenge/info.csv). It would be best to begin analyzing the script and seeing what occurs during its execution to start determining what is causing issues. ***NOTE: Do not execute the python script as root since this will not give you the expected output required for this challenge.** The user's [zip python environment](challenge/python3.9.zip) is also included.

  ## Token Format
 
  There are 4 parts in total. Parts 1, 2 and 3 will check for the relative path of each file containing malicious code.
  
  The 4th part will check for the relative path that was entered to overwrite certain environment variables.
