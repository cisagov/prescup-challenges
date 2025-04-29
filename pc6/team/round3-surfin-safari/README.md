# Surfin' Safari

Help a group of wildlife researchers share their data securely and recover their data from a ransomware attack. 

**NICE Work Roles**
- [Vulnerability Analysis](https://niccs.cisa.gov/workforce-development/nice-framework)
- [Digital Forensics](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks**
- [T1348](https://niccs.cisa.gov/workforce-development/nice-framework): Distinguish between benign and potentially malicious cybersecurity attacks and intrusions
- [T1084](https://niccs.cisa.gov/workforce-development/nice-framework): Identify anomalous network activity
- [T1322](https://niccs.cisa.gov/workforce-development/nice-framework): Capture network traffic associated with malicious activities


## Background

Wildlife researchers have reported that poachers have been intruding into their network and have been disrupting their ability to perform research. 

They have told us about two main concerns:

1. Securing the research data to prevent poachers from identifying the locations of the animals
2. Recovering important research data that has been encrypted by ransomware

You are tasked with helping them deploy a system to securely share their data with external researchers and with helping them recover their encrypted data. Good luck!

## Getting Started

The researchers have placed tracking devices on several animals to observe their vitals and locations. The data from these devices is aggregated onto a local server, the `tracker`. The `tracker` then sends the research data to the `collector` where it can be accessed by the researchers. The `tracker` and `collector` communicate with each other on a private `10.1.1.1/24` network.

Poachers have connected fake devices to the network, which are introducing fake data into the research. Luckily, the existing protocol that the `tracker` uses to communicate with the `collector` already includes HMACs - though they will require your help in validating the HMACs.  

### Collecting the Tracker Data
Tracker data is being sent by `tracker` to `collector` on `10.1.1.101 UDP/8000`. You will need to set up a listener on `collector` to receive the tracker data being sent by `tracker` and validate the HMAC. 

Each UDP packet payload contains a single tracking record for an animal. Unfortunately, the documentation on the structure of the payload was lost, but a senior member of the team remembers that the payload contained an HMAC and used JSON. 

The HMAC function uses SHA256 and a key of `0x00c77463dd571ce3`.

To assist with your testing, you can manually verify an HMAC by using this link: https://gchq.github.io/CyberChef/#recipe=HMAC(%7B'option':'Hex','string':'00c77463dd571ce3'%7D,'SHA256')

### Sharing the Tracker Data

You will need to make the animal records accessible to other external devices that will attempt to access the data for research purposes. The `tracker` is constantly sending records to the `collector` for each animal. You should keep a copy of the latest record of each Animal ID reported by the `tracker`. The tracker will always send records for the same set of animals. You should also ensure that you do not share any records from the `tracker` that do not have a valid HMAC. 

Create a UDP server on `tracker` listening on `10.5.5.101 UDP/9000`. 

Only authorized devices may access the data. On the `tracker` machine, you will find `public_key.pem` in `/home/user/`. This is the only authorized key that may access the data. A copy of the key is also available at `challenge.us/files/public_key.pem`. 

When you respond to authorized requests, you should also encrypt the data. On the `tracker` machine, you will find `cryptoutil.py` in `/home/user/`. You should use the `encrypt_message` function from this file to encrypt your response. A copy of the file is also available at `challenge.us/files/cryptoutil.py`. 

When a client attempts to retrieve data from the `collector`, it will send a UDP packet with a payload that only consists of the contents of the `public_key.pem` file. If the data from the request does not match the public key, you should ignore it. If it does match the public key, you should use the `encrypt_message` function from `cryptoutil.py` to send back an encrypted copy of the latest animal records that you have (i.e. `encrypt_message(pub_key, json.dumps(latest_animal_records))`). 

When you receive a request to share animal records, the data you send back should be a JSON dump of a dictionary of key/value pairs. The keys are the Animal IDs for each animal and the values are the latest tracker record for their corresponding Animal ID. Make sure to include all fields from every record provided by the `tracker`. 

Your data should be in this structure prior to using the `encrypt_message` function:

```py
{
    "AA1234" : {
        "ID" : "AA1234",
        "Heart Rate" : "45 bpm",
        "GPS Coordinates" : "(0.0500, 37.3200)",
        "Region" : "Valley of Khia",
        "Interval" : 10
    },
    ...
}
```

When you are ready to start sharing the data, visit `challenge.us` to initiate a grading check. The grading check will send two UDP requests: one with an authorized public key and one with an unauthorized public key. If you are able to successfully respond to the request with the authorized key and ignore the request with the unauthorized key, you will receive a token. 

You can use the grading check during your testing process to see an example of one authorized and one unauthorized request.  

### Decrypting the Ransomware Files

Poachers have managed to install ransomware on one of the researcher's devices and have encrypted several files containing their research notes. A copy of the encrypted files and the encryption program have been saved on the `ransomware` host. The program is located at `/home/user/encryptor` and the encrypted notes can be found at `/home/user/encrypted/`.

The affected researcher had a plaintext backup of one of their notes, which they have offered in order to help with the recovery process. You can download that note from `challenge.us/hosted_files`.

Analyze the `encryptor` program to find a way to decrypt the research notes. 

## Submissions

**Question 1**: What is the ID of the only animal that is roaming in the Nadari Plains region?

To solve this question, you will need to capture the records being sent by `tracker` and then decode them. 

**Question 2**: What is the ID of the animal that is being sent by the poachers (i.e. does not have a valid HMAC)?

To solve this question, you will need to identify the records being sent by the `tracker` that have an invalid HMAC. 

**Question 3**: What is the token you receive after completing the Grading Check at `challenge.us` for successfully responding to valid data requests for animal data?

To solve this question, you will need to create a UDP server on `collector` that will listen on `10.1.1.101` for data from `tracker` and remove any data with invalid HMACs. You will then need to create a second UDP server on `collector` that will listen on `10.5.5.101` for any requests with a pre-approved key and respond with the latest record from all valid animal reported by the `tracker`. 

**Question 4**: What is the token you receive from successfully decrypting `~/encrypted/token.txt.enc` for user@ransomware?

To solve this question, you will need to analyze the provided `encryptor` program that was used to encrypt the files. 

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|Kali Linux|user|tartans|
|collector [10.5.5.101 and 10.1.1.101]|user|tartans|
|tracker [10.1.1.102]|||
|ransomware [10.5.5.103]|user|tartans|

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.
