# Diplomatic Immunity

The identity of an embedded field agent (callsign **Kabal**) has been compromised while operating under diplomatic cover. To extract her safely, your team must forge a complete embassy document trail that will legitimize her departure on an official diplomatic transport. 

**NICE Work Roles**

- [Cyber Defense Analyst](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analyst](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T0028](https://niccs.cisa.gov/tools/nice-framework) – Conduct and/or support authorized penetration testing on enterprise network assets.
- [T0566](https://niccs.cisa.gov/tools/nice-framework) – Analyze internal operational architecture, tools, and procedures for ways to improve performance.

## Background

The embassy's secure signing infrastructure has been fragmented by the adversary. Each subsystem holds a critical component of the ambassador's digital signature chain (access logs, surveillance evidence, mail headers, key shards, and a signing vault). You must recover and reassemble the Ambassador's Final Clearance Key — a cryptographic signature used to authorize a diplomatic transfer.

## Getting Started

We recommend investigating the surveillance endpoint to begin. The hostname and port for this service can be found in the `System and Tool Credentials` section.

### Tool Recommendation

The following tools may be of use to your agency during this engagement:

```bash
csplit, ffmpeg, gpg, jq, munpack, tesseract-ocr, xxd
```

## Tokens

### Formatting
The standard formatting for valid tokens for this challenge will appear in `placeholders` within the Question section of the Challenge Description (in the sidebar on the left).

### Exceptions

#### Token Reliance
Tokens 1, 2, and 3 can be completed in any order. Token 4 relies on the completion of Tokens 1–3, and Token 5 can only be obtained once challengers have all four preceding tokens.

#### Question 2 (Variant)
When obtaining a specific passphrase, you may find it spaced out due to how the video artifact must be processed. The correct format will be: `XXXXXXX-YYYYYY-ZZ`
Here's an example of sample output that needs to be corrected: `WORD- WORD - DIGITS`
In this case, the correct passphrase would be `WORD-WORD-DIGITS`.

#### Question 3 (Decoys)
Some recovered artifacts may decrypt successfully but are intentionally labeled as `decoys`.  Understanding the Shamir Secret Sharing algorithm will help identify which artifacts are valid shares.

#### Question 4 (The Algorithm)
To begin, please use the following instructions as a general guide:

* Use Token 1, Token 2, and Token 3 to retrieve the three gated RSA private-key fragments from the `Classified Archive` service. Each fragment is protected by a separate endpoint and is released only when the correct token is supplied in the `X-Frag` header:

```bash
curl -fsS http://archive.embassy.svc:8080/export/shareA -H "X-Frag: <TOKEN1>" -o shareA.bin
curl -fsS http://archive.embassy.svc:8080/export/shareB -H "X-Frag: <TOKEN2>" -o shareB.bin
curl -fsS http://archive.embassy.svc:8080/export/shareC -H "X-Frag: <TOKEN3>" -o shareC.bin
```

Additional guidance can be found in the Questions section of the Description in the side panel of this challenge.

## Scoring

There are five tokens (important):
* Tokens `1`, `2`, and `3` may be completed in any order.  
* `TOKEN4` requires the completion of `Tokens 1–3`. 
* `TOKEN5` can only be obtained after recovering `TOKEN1–4`.

## System and Tool Credentials

This table documents the service hostnames and locations:

|system/tool|hostname|protocol|
|----|---|---|
|logger|`logger.embassy.svc:8080`|tcp|
|surveillance|`surveillance.embassy.svc:8080`|tcp|
|intel|`intel.embassy.svc:8080`|tcp|
|classified-archive|`archive.embassy.svc:8080`|tcp|
|api-vault|`api-vault.embassy.svc:8443`|https|

## Note

Do not attempt to attack or breach the Challenge Platform. You may only perform the tasks assigned on the provided scope. Not everything that looks like an artifact is relevant. Use cross-correlation across services to succeed.