# OpenSSL && Open Sesame

Decrypt AES-256 files with help from passwords, salts, IVs, keys, and logs.

**NICE Work Role:** 

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

**NICE Tasks:**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Conduct and/or support authorized penetration testing on enterprise network assets.  
- [T0572](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0572&description=All) - Apply cyber collection, environment preparation and engagement expertise to enable new exploitation and/or continued collection operations, or in support of customer requirements."

## Background
You are conducting a penetration test. Your team has accessed encrypted files. If you are able to crack this data at rest, then the penetration test is a success as you've shown that the data the client prioritizes was lost and compromised.

## Getting Started
There are five directories that contain encrypted files and associated information/files inside of the [challenge folder](challenge). Answer the questions below as you decrypt the files. 

## Questions

### Stage 0: 
- Decrypt `email2.txt.enc` with passphrase `tartans`. 
- **Provide only the username of the email address** 
  - (the part before the `@` sign)

### Stage 1: 
- Decrypt `id10.txt.enc` with the key and IV also located in the directory. 
-  **Provide the decrypted output**

### Stage 2: 
- Decrypt `PIN20.txt.enc`. Potential Keys and IVs are located in the directory.
- **Provide the decrypted output**

### Stage 3: 
- Decrypt `phone232.txt.enc`. Keys, IVs, and Salts that may have been utilized are located in the directory. 
- **Only record numbers, no dashes or other special characters** 

### Stage4: 
- Decrypt `fingerprint_b64_464.txt.enc`. There is an encryption.log that details enough specifics on how the various data was encrypted. 
- **Provide the decrypted data as a base64 encoded string** 
