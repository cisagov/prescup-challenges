# Going Nuts in Romania

Players must respond to an incident involving both external and internal parties.

**NICE Work Roles**  

- [Cyber Defense Incident Responder](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Incident+Responder&id=All)  

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)  



**NICE Tasks**
- [T0166](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0166&description=All) - Perform event correlation using information gathered from a variety of sources within the enterprise to gain situational awareness and determine the effectiveness of an observed attack.
- [T0295](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0295&description=All) - Validate intrusion detection system (IDS) alerts against network traffic using packet analysis tools.
- [T0214](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0214&description=All) - Receive and analyze network alerts from various sources within the enterprise and determine possible causes of such alerts.

## IMPORTANT

This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

You have been called to assist in investigating an incident spanning multiple systems and timezones. The network appears to have been compromised by an external attacker who was able to extract data via the Internet while working in conjunction with a malicious insider believed to be upset with the duration of their work abroad.

You will be provided with:
1. The full IDS (Garlic) and packet capture (found on the Desktop of Garlic) of the external activities
2. Access to the domain controller (ALPHA) event logs and a password cracking wordlist (found on the CD attached to Vlad and Sanguine)
3. The compromised internal system itself (Vampiric).

Unfortunately, due to the disparate nature of the network, a map is not available, though should not be necessary. The domain systems are located in NYC, and the remote users were stationed in Romania and connected via VPN.

All events are believed to have begun around 1:25 PM EDT on October 7th, 2021. This corresponds to night time (~8:25 PM) in Romania where staffing is minimal. You only need to focus on events occurring at/after this date/time.

A complete remote user list for those who had access to the compromised system is as follows:
cbrown, franklin, lvp, marcie, pmint, ppen, sbrown, beethoven, shermy, snoopy, woodstock

franklin also serves as the local administrator for the compromised system

You have the authorization to logon as these accounts to verify information and conduct your investigation.

## Note
While forensics tools are available, they should not be necessary to solve the challenge. Everything can be answered with the evidence and systems provided as is.

Additionally, due to the age of the Domain Controller (ALPHA), event viewer on Vlad cannot be used to open its log files. However, Timeline Explorer on Vlad can be used as a "cleaner" CSV file viewer when compared to tools like Notepad++ or OpenOffice Calc on Sanguine.
