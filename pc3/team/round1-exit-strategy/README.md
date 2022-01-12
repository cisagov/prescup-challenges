
# Exit Strategy

  Given a degraded corporate LAN, you must fix the networking issues and identify any adverse activity.


  **NICE Work Role:**

  [Network Operations Specialist](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Network+Operations+Specialist&id=All)

  [Cyber Defense Analyst](https://niccs.us-cert.gov/workforce-development/nice-framework/workroles?name_selective=Cyber+Defense+Analyst&fwid=All)


  **NICE Tasks:**

  - [T0035](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=All&description=T0035) - Configure and optimize network hubs, routers, and switches(e.g., higher-level protocols, tunneling).

  - [T0081](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=All&description=T0081) - Diagnose network connectivity problem

  - [T0162](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=All&description=T0162) - Perform backup and recovery of databases to ensure data integrity. 

## Note

  This challenge guide is, aside from this note, unmodified from its original version in the competition. Since the challenge requires specific system configurations, it was not reasonable to release it in a playable state. The full version of this challenge can be played on the hosted site.

  ## Background

  Westport has contacted you because their network has recently become unusable.  Their network administrator recently quit and threatened to "expose the company". 

  They have asked you to fix their networking and confirm that nothing nefarious happened.


  ## Getting Started
  The network administrator was responsible for maintaining the VYOS Routers and the pfSense firewall.  They recently switched the network over to use OSPF and BGP.

  Users are currently reporting the following problems:

  - No internal users can connect to any internal DMZ services or the internet
  - Maintenance users are reporting no outbound network connectivity
  - IT users are reporting no outbound network connectivity
  - Customers are reporting that the company website is available, but no other public facing services are available

  The company provided you the following network map(only hosts relevant to the challenge are shown):
![t09-b04fd5a7.png](https://topomojo.cyberforce.site/docs/f5009220-84f7-41c7-97af-9dfe4752e09a/Screen_Shot_2021-07-07_at_3.14.44_AM-1469882458.png)

  **Important**: Because the network is degraded, you may not be able to access some GUIs, consoles, or websites that you would normally be able to. Parts of the network may have to be fixed in order to restore connectivity to vital services.


  ## Submission Format

  Scoring for this challenge will consist of 4 grading checks and 2 scenario-based questions.  

  Grading checks can be assessed by visiting the grading site located at `http://challenge.us`. This is where you can see the challenge completion status and receive submission tokens. Submission tokens will be 16 character hex strings. Paste submission tokens into their respective fields below to earn points. 

  - NetworkCheck1 verifies BGP advertisement configurations
  - NetworkCheck2 verifies OSPF configurations
  - NetworkCheck3 verifies NAT configurations
  - NetworkCheck4 verifies VyOS router configurations


**Do *NOT* configure bridging on any of the systems as that will result in losing access to the VMs and the Gamespace.**

## Note
Attacking or unauthorized access to challenge.us (10.0.1.100) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

  ## System Credentials

  | system | username | password |
  |----------|---------|----------|
  | vyos-1 | vyos | vyos |
  | vyos-2 | vyos | vyos |
  | vyos-3 | vyos | vyos |
  | pfsense | user | tartans |
  | win2019-web1 | Administrator | tartans@1 |
  | win2019-dc1 | Administrator | tartans@1 |
  | db | user | tartans |
  | windows 10 workstation | user | tartans |
