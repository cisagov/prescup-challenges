# Operation Blackjack

Someone is running an illegal casino! Find the casino, exploit any vulnerability you can, and obtain the decryption key.

**NICE Work Roles**

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/work-roles/exploitation-analyst)

 **NICE Tasks**

- [T0641](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0641) - Create comprehensive exploitation strategies that identify exploitable technical or operational vulnerabilities.
- [T0736](https://niccs.cisa.gov/workforce-development/nice-framework/tasks/t0736) - Lead or enable exploitation operations in support of organization objectives and target requirements.

## Background

The Aurellians want to know who is responsible for running an illegal gambling ring on the space-station-gtwpi system. Reconnaissance has captured a conversation that incriminates the ring leader; but, the conversation is encrypted. Information on the software being used by the casino was also captured and a janitor account on the space-station-gtwpi system has been provided. Find the casino, exploit any vulnerability in the system, and obtain the decryption key.

## Getting Started 

The mission consists of three parts:

- **Part 1:** Remotely connect to `space-station-gtwpi` via SSH and identify the full path to the directory hosting the secret casino.
- **Part 2:** Find a vulnerability or weakness in the casino that you can exploit to gain access to the criminals' inner circle.
- **Part 3:** Find an RSA private key from somebody in the inner circle to decrypt transmissions. The casino suffered some data loss after a hardware error so you may have to fix corrupted files.

You are provided the encrypted communications and the source code to one of the casino games we acquired. These files are available at `https://challenge.us/files`. It may take a few minutes for these files to become available.

## Challenge Questions

To grade this challenge offline, run the grading script:

```bash
chmod +x grade.sh
./grade.sh
```

1. What is the location of the files running secret casino? Please provide the full path to the directory hosting the casino. 
2. What is the token found in the Casino Manager's home folder?
3. After decrypting the communications, enter the password to the financial logs that the aliens provided.
