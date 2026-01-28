# Monkey in the Middle

While attending your annual spy training, you made an offhand comment about loving the game "Monkey in the Middle" as a child. Prove you're still at the top of your game by using multiple spoofing 
techniques to eavesdrop, tamper, and steal a secure browser cookie.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities
- [T0591](https://niccs.cisa.gov/tools/nice-framework): Perform analysis for target infrastructure exploitation activities


## Background

While enjoying a short lunch break at the mandatory annual spy training, you make an offhand comment about loving the game "Monkey in the Middle" as a child. The instructor makes a weird face and runs from the room, cackling like a maniac and muttering "MitM". The next day, you find the lesson plan has been replaced with a hands-on workshop all about spoofing, intercepting, and tampering with communication on a local network! The instructor challenges you to prove you're still a champion at "Monkey in the Middle" by stealing a `SameSite: Strict` cookie from his browser.

## Getting Started

Use the provided Kali machine to access the workshop's network. The instructor reminds you that **forwarding is enabled by default** on the device. The instructor also tells you that there are six other hosts on the network:

1. `mathserver.pccc`, running a custom `TCP` server on port `9000`
2. `mathclient.pccc`, opens a connection to `mathserver.pccc`
3. `dnsmasq.pccc`, provides DNS via `dnsmasq`
4. `dnsvictim.pccc`, uses the DNS service from `dnsmasq.pccc`
5. `web.pccc`, hosts a simple web server
6. `webvictim.pccc`, which uses Selenium to browse `web.pccc`

## Tokens

The instructor provides a list of tokens to retrieve from these devices. The tokens are formatted as `PCCC{some_words_here_??_????}`. *Token 3 uses the alternative format `PCCC-some-words-here-??-????` to be a valid domain name.* 

Note the following tokens may be collected in any order, although they are designed to naturally lead up to the final task.

No grading is required.

1. Intercept the token sent by `mathclient.pccc` to `mathserver.pccc` on port `9000`.
2. The `mathserver.pccc` will send this token when all of the math questions passed between `mathclient.pccc` and `mathserver.pccc` are answered correctly.
3. Intercept the `DNS` request from `dnsvictim.pccc` and find this token in the first label of the domain name. 
    - This token uses the alternative format `PCCC-some-words-here-??-????` to be a valid domain name.
4. After a successful `DNS` lookup, the `dnsvictim.pccc` host tries to send this token to port `9001` at `{token3}.target.pccc`
5. This token is in the header of the `HTTP` request sent by `webvictim.pccc`.
6. The `webvictim.pccc` host types this token into the `textarea` on the page retrieved from `web.pccc`.
7. Combine all of these skills to steal a cookie from the `webvictim.pccc` host. 
    - The cookie is named `tokenLax`, and belongs to the domain `external.target.pccc` on port `80`. 
    - This cookie is marked as `SameSite: Lax`.
8. Combine all of these skills to steal a cookie from the `webvictim.pccc` host. 
    - The cookie is named `tokenStrict`, and belongs to the domain `external.target.pccc` on port `80`. 
    - This cookie is marked as `SameSite: Strict`.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-vnc|user|password|
