# We Must Go Deeper

Alien field agents are in communication with their handlers, whom we have
placed under surveillance. We presume they are somehow in touch with their
superiors, some of whom are, presumably, located on the moon base. We have
contacted the handlers' ISPs and collected network flow data. We need you
to backtrace their communications, and identify any IP addresses of their
leadership and any communication infrastructure used to stay in touch with
same.

**NICE Work Roles:**

-  [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0027](https://niccs.cisa.gov/workforce-development/nice-framework) of a network intrusion.
- [T0240](https://niccs.cisa.gov/workforce-development/nice-framework) - Capture and analyze network traffic associated with malicious activities using network monitoring tools.


## Background

You are given access to a copy of `netflow.tar.xz`, an archive containing
netflow data collected from the ISP of each of the suspected alien handlers:

| handler | IP address     |
| ------- | -------------- |
|    NA   | 128.237.119.12 |
|    EU   |    2.69.27.123 |
|    AS   |  1.235.189.106 |
|    OC   |  58.172.47.117 |
|    AF   |   45.104.34.74 |
|    SA   |  152.200.19.77 |

## Getting Started

Using the `nfdump` utility, start by locating any IP addresses that appear
to serve as communication infrastructure between the alien handlers and
their moonbase leadership. Subsequently, also identify the IP addresses
used by leadership to coordinate the handlers' activity.

*You can install nfdump on Ubuntu systems by using the command:* `sudo apt-get install nfdump`

## Submission Format

Run the grading script provided in the `solution` directory
(SPOILER ALERT: the script itself contains a copy of the answers!)
and submit any IP addresses you identified as (space-separated)
command line arguments to the script.
Your score will be calculated automatically, with points awarded for
correctly identified IP addresses, and deductions for misidentified IPs.
