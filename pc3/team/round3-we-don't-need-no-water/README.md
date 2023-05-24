  # We Don't Need No Water

  Your team is given the responsibility of keeping an old, unfixable
  service running, in spite of reports of known zero-day vulnerabilities
  being actively exploited in the wild. The service is located on a
  private subnet behind an Ubuntu based port-forwarding DNAT firewall.
  You are provided with a malicious request generator captured from an
  infected embedded device by your intelligence team. Your job is to
  reverse-engineer the nature of four different ways of causing a server
  failure, and use the Ubuntu firewall to filter out only malicious
  packets, maintaining availability for all legitimate users.

  **NICE Work Roles**

  - [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

  - [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

  **NICE Tasks**

  - [T0117](https://niccs.cisa.gov/workforce-development/nice-framework) - Identify security implications and apply methodologies within centralized and decentralized environments across the enterprise's computer systems in software development.

  - [T0118](https://niccs.cisa.gov/workforce-development/nice-framework) - Identify security issues around steady state operation and management of software and incorporate security measures that must be taken when a product reaches its end of life.

  - [T0175](https://niccs.cisa.gov/workforce-development/nice-framework).

  - [T0182](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform tier 1, 2, and 3 malware analysis.

  ## IMPORTANT

  This challenge is only partially open sourced. The files in the [challenge directory](challenge) are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

  ## Background

  Each team member is given access to a `user` (Kali) machine which contains
  the necessary development tools (Ghidra, gcc) to analyze the captured exploit
  and develop a solution. There is also source for a userspace netfilter
  program which was used to protect a previous zero-day exploit against the
  service, which has since been fixed. From each `user` machine, you can ssh
  into the Ubuntu firewall (hostname `svcnat`), where additional filtering may
  be provisioned to protect the service.

  The server listens on TCP port 31337, and expects a 32-character request,
  to which it replies with a 32-character answer string. You may try this by
  issuing the following command from your `user` machine:

  ```
  echo '00112233445566778899aabbccddeeff' | nc -i 6 svcnat 31337
  ```

  Normally, the server will reply with another 32-character string, and close
  the connection. In certain rare cases, the server will reply with the string
  `FAIL`, indicating that an exploit was completed successfully. If a 32
  character request isn't received within up to 5 seconds, the server will
  reply with the string `TIMEOUT`.

  Code for the server and vulnerability is provided within the [challenge directory](challenge). Compile the server code using the following command:
  ```
  gcc -o pc3t24_srv pc3t24_srv.c -lcrypto -static -Wall
  ```

  Then run `pc3t24_srv.service` as a service to run the server. 

  **Note:** The firewall is not provided. The full challenge can be completed on the hosted site.

  ## Getting Started

  Your goal is to first figure out the four different ways of generating
  malicious exploit strings (those that would result in the server responding
  with `FAIL`). For this, you may use Ghidra to decompile one of the malicious
  string generator samples available in the [Challenge folder](./challenge).

  Next, write a userspace filter program that would drop those requests as
  they are intercepted on the `svcnat` firewall, causing the malicious request
  to time out instead. Ensure that all non-malicious requests are sent through
  to the server, and 32-character replies are allowed back through `svcnat`.

  ## Submission Format

  Visit the grading site located at `http://challenge.us` inside the hosted environment, where you can see
  the challenge completion status and receive submission tokens, in the form
  of 8-digit hexadecimal strings.

  There are four (4) grading checks for this challenge. No points are awarded
  if any legitimate requests are dropped. One token worth a quarter of the
  total points is awarded for each of the four exploit variants successfully
  dropped by your firewall program.

  ## System Credentials

  | system | username | password |
  | ------ | -------- | -------- |
  | user   | user     | tartans  |
  | svcnat | user     | tartans  |
