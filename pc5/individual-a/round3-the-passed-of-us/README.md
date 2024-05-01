# The Passed of Us

Perform credential vault recovery in order to gain access to a data recovery website and analyze backup data for crucial information. Scripting will be necessary to perform the key derivation process to unlock the vault.

**NICE Work Role**

- [Cyber Defense Forensics Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**

- [T0049](https://niccs.cisa.gov/workforce-development/nice-framework): Decrypt seized data using technical means.
- [T0103](https://niccs.cisa.gov/workforce-development/nice-framework): Examine recovered data for information of relevance to the issue at hand.
- [T0238](https://niccs.cisa.gov/workforce-development/nice-framework): Extract data using data carving techniques (e.g., Forensic Tool Kit [FTK], Foremost).


## Background

Crew member Marcus Kinkaid has been unreachable while on leave to the planet Pandora. Marcus is the only person with access to data backups, which include accidentally deleted information related to a critical medical mission. Thankfully, we have access to Marcus' system registry and credentials vault. Crack his vault, recover his credentials, and access our backups in his absence.

## Getting Started

Retrieve Marcus' encrypted **vault** file and **registry** from `https://challenge.us`. The **LostPass** application also stores secrets information generated during account creation on our local spaceship site at: `http://secrets.merch.codes:8080` (10.3.3.145).

Using this information, derive the vault's symmetric encryption key to recover Marcus' credentials. We know a few things about how LostPass derives its keys:

- It concatenates the MD5 hash of the user's vault password, the MD5 hash of the user's secret, and a salt unique to each iteration; the order is unknown.
- It calculates the MD5 hash of this entire concatenated 96-character string for each iteration and uses the resulting hash as the new salt in the next iteration of the overall process.
- The resulting salt after the final iteration is complete becomes the key to encrypt/decrypt the vault.

After finally accessing the data recovery site and backups, scour the backups for evidence of PDF files deleted on **February 28** and analyze these files for information relevant to the  medical mission.

## System Tools and Credentials

| system | OS type | username | password |
|--------|---------|----------|--------|
| Kali | Kali | user | tartans|

## Note

Attacking or unauthorized access to `challenge.us` (`10.5.5.5` or `64.100.100.102`) is forbidden. You may only use the provided webpage to view challenge progress and download any challenge artifacts that are provided.

## Challenge Questions

1. What is the token associated with Marcus' secret?
2. What is the token found inside the vault along with the recovered credentials list?
3. Which planet is the patient codenamed "Ness" headed to in order for us to extract him?
