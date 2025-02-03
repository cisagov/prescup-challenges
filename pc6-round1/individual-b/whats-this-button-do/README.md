# What's This Button Do?

Perform reverse engineering to extract data and exploit a server.

**NICE Work Roles**

- [Cyberspace Operations](https://niccs.cisa.gov/workforce-development/nice-framework/)
- [Exploitation Analysis](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1671](https://niccs.cisa.gov/workforce-development/nice-framework/): Exfiltrate data from deployed technologies
- [T1690](https://niccs.cisa.gov/workforce-development/nice-framework/): Identify exploitable technical or operational vulnerabilities


## Background

Key exchange is fundamental to secure network communication. This challenge introduces a simple implementation of key exchange.

## Getting Started

1. On the `kali` VM, open a browser and navigate to `challenge.us`.
2. Follow the instructions in the prompts. For **Part 2**, no input is required in the text box; grading is automatic.
3. After reviewing the requirements for each part, proceed to the hosted file page at `challenge.us/files`.
4. Download at least the **client** file. The **encode_bytes.py** script may help with encoding **Part 1** bytes as specified.

### Additional Notes

- The remote server is single-threaded and handles one connection at a time. If it appears unresponsive, check for active connections in other terminal tabs.
- `rustup` with the latest toolchain is pre-installed and includes useful tools for this challenge.

## Challenge Questions

This challenge contains **two** tokens: one for each part. Tokens are issued on the grading page at `challenge.us` upon successful completion. All tokens are 16-character printable ASCII hex strings.

1. Submit the part 1 token from challenge.us.
2. Submit the part 2 token from challenge.us.