# Picky PKI

A bad certificate is on a webserver. Obtain and apply a signed one applied using a custom protocol. Additional tasks build on this.

**NICE Work Roles**

- [Cyber Defense Infrastructure Support Specialist](https://niccs.cisa.gov/tools/nice-framework/)

**NICE Tasks**


- [T1553](https://niccs.cisa.gov/tools/nice-framework/): Configure and maintain PKI and certificate services
- [T1422](https://niccs.cisa.gov/tools/nice-framework/): Implement and manage secure authentication mechanisms
- [T1326](https://niccs.cisa.gov/tools/nice-framework/): Apply cryptographic techniques to protect data


## Getting Started
You are tasked with fixing a web service that has been running with a bad TLS configuration. Currently, it has an expired and untrusted certificate. A private Certification Authority service is running in the environment. It does not issue certificates in a normal way. You must figure out its custom protocol to request a valid certificate. A grader service will test the live site to verify if it is serving a valid certificate.

## Tokens:

1. Use the `ca_service` machine to obtain a signed certificate for `webserver`. SNI matters. Run the grader at `http://grader:8080/` to get your token. 
    -   You can find initial information located at `http://ca_service/pubkey`.
    -   You can get your signed certificate from `http://ca_service/sign-x509`.

1. Enforce mTLS and OCSP stapling (Must-Staple). Run the grader at `http://grader:8080` to get your token.
    -   You can get the root certificate from `http://ca_service/ca.crt`

1. Build an HPKE sealed message using the advertised suite for the oracle endpoint. The endpoint accepts your sealed box and returns your token. Key items you need for this will start with "HPKE-STEP3-" and end with the data you need.

    - This is only solvable after you have a valid certificate.
    - To find out more about your HPKE message recipient, you can gather information from `https://webserver/hpke/pub`.
    - You need to send your message to `https://webserver/hpke/unseal`.

## Credentials:

|Asset|username|password|
|---|----|-------|
|Kali | user | password|
|webserver|user|password|
|`http://grader:8080`|||