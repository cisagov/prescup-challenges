# Phreaky Friday

Five voices. One conspiracy. Hear the clues, crack the tokens. Reveal the true nature of the “lottery.” 

**NICE Work Roles**

- [Digital Forensics](https://niccs.cisa.gov/tools/nice-framework)
- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)

For more information on these roles, please visit: https://niccs.cisa.gov/tools/nice-framework.

**NICE Tasks**

- [T1091](https://niccs.cisa.gov/tools/nice-framework): Perform authorized penetration testing on enterprise network assets
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
- [T1383](https://niccs.cisa.gov/tools/nice-framework): Utilize deployable forensics toolkit

## Background
📱 You are a Senior Forensics Analyst at Azul Corporation that has deep ties into the Intelligence Community. A fellow Analyst claims that they received notification by phone that they “won the lottery”; however, no state lottery events have occurred this week. Over time, they began acting strangely and working odd hours. Executive management identified you as the best analyst on staff. As a result, The Federal Bureau of Discovery (FBD) has reached out and tasked you with obtaining the hidden messages (tokens) from audio correspondences and images they were able to find for your examination. After this engagement, the Bureau will use these clues to decrypt an encrypted invitation from a secretive spy consortium called The Accord. Each artifact is a voice artifact or a trace of a voice session using unfamiliar and, oftentimes, custom voice protocols.

## Getting Started

To get started, simply navigate to your Evidence Dashboard located at `http://dashboard.pccc` to begin the challenge. Download the Evidence Package for this challenge's artifacts and the `mission briefing` which provides you with specific instructions that will need to be expounded upon to successfully complete each objective.

When using the CLI version of this tool, the possible statuses are presented below:

* {"ok":true,"message":"CORRECT"} — success
* HTTP 400 {"detail":"INVALID_TOKEN"} — wrong
* HTTP 400 {"detail":"CRC_MISMATCH"} — checksum mismatch
* HTTP 429 {"detail":"RATE_LIMIT"} — rate limit exceeded

### Token Format

The token format for this challenge is as follows: `PCCC{PHR-XXXXXX}`

#### Token 5 (IMPORTANT)

You will recover the inner part of the token: `PHR-XXXXXX`. You must wrap that inner value with `PCCC{}` in order to get the correct score.
For example, if `PHR-449GCA` is recovered, TOKEN5 becomes `PCCC{PHR-449GCA}`.

## System and Tool Credentials

|system name|location|
|-----------|--------|
|Evidence Portal|`http://dashboard.pccc`|

## Note

Attacking the President's Cup Grading Server or Challenge Platform is unauthorized and considered out of scope.
