# Spot the Super!

Develop an IDS rule to alert on PostgreSQL superuser account creation. Familiarity with Suricata/Snort expected (PostgreSQL experience is a plus).

**NICE Work Role:** 

- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst)

**NICE Tasks:**

- [T0023](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0023&description=All) - Characterize and analyze network traffic to identify anomalous activity and potential threats to network resources.

- [T0295](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0295&description=All) - Validate intrusion detection system (IDS) alerts against network traffic using packet analysis tools.  

- [T0310](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0310&description=All) - Assist in the construction of signatures which can be implemented on cyber defense network tools in response to new or observed threats within the network environment or enclave.  

## Background

Your organization uses PostgreSQL as the back-end database supporting a
variety of services. For convenience, database administrators are allowed
to connect to the PostgreSQL server in superuser mode, in order to perform
various maintenance tasks.

Your security department is, however, concerned about malicious insiders
or an administrator's potentially compromised machine creating additional,
"back-door" accounts with superuser privileges. A Suricata-based intrusion
detection system (IDS) is currently deployed to monitor traffic entering
and leaving the datacenter hosting (among others) the PostgreSQL database
servers.

As one of your organization's Cyber Defense Analysts, you have been asked
to develop a new IDS rule which would issue an alert whenever a new database
account (a.k.a. role) is created with superuser privileges.

**NOTE**: For simplicity, you are **not** required to issue alerts when
superuser privileges are added to an __existing__ database account!


## Getting Started

To set up this challenge, you must have a linux VM with suricata installed and running. The following commands will set it up:

```
sudo apt install suricata

service suricata start
```
In the [challenge](challenge) folder you will find the following files:

- [example.sql](challenge/example.sql): log of a PostgreSQL superuser session during which a subset
    of a table's columns are listed, a regular (non-superuser) account named
    `foo` is created, and a superuser privileged account (`abc`) is created.
- [example.pcap](challenge/example.pcap): a packet capture of the above-mentioned PostgreSQL session.
- [example.rules](challenge/example.rules): a sample Suricata rule alerting whenever a superuser
    account connects to the database server.



  The rule you must create to complete the challenge should be a file containing a single line of ASCII text.  



**HINT**: You are encouraged to open [example.pcap](challenge/example.pcap) in Wireshark and study
the composition and structure of the various queries in order to fine-tune
your IDS rule! Also, you may wish to visit the following links for information
on how to write good content matching statements as part of a Suricata/Snort
IDS rule:

- [Suricata payload keywords](https://suricata.readthedocs.io/en/suricata-5.0.3/rules/payload-keywords.html)
- [Keywords: offset/depth/distance/within](https://blog.joelesler.net/2010/03/offset-depth-distance-and-within.html)

Develop your superuser account creation alert rule in a separate file (named e.g., `super.rules`), and test it by running:


```bash
mkdir logs
sudo cp super.rules /etc/suricata/rules/suricata.rules
sudo suricata -r example.pcap -l logs
cat logs/fast.log
```


Examine alerts appended to `logs/fast.log` to test the functionality of your
rule. 


## Submission Format

To Grade your submission, run the grade_it.sh script in the grading_script folder as sudo using your filename as a parameter.  Example below using rule file as the submission

```bash
sudo ./grade.sh "$(<super.rules)"

```


You may do this as many times as necessary: your rule will be tested against
a number of different cases. Points are awarded for correct identification of true positives/negatives and avoidance of false positives/negatives. 

- True Positive: Your rule alerts upon superuser account creation
- True Negative: Your rule does not alerts when no superuser account is created
- False Positive: Your rule alerts when no superuser account is created
- False Negative: Your rule does not alert when a superuser account is created


The maximum number of tokens issued is 5, for a rule which alerts on all instances of
superuser account creation, and generates no false positives.


