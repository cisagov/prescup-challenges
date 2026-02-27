# Inception

"Dreams feel real while we're in them. It's only when we wake up that we realize something was actually strange." Enter into the dream space of the President's Cup challenge developers and hack into last year's competition site!

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities

## Background

You've been contracted by a shadowy organization to implant ideas into the subconscious of a wealthy business owner. However, the operation was a bust, and you've somehow found yourself trapped in the dream space of the challenge developers on the President's Cup team! Of course, like the singularly focused fellows that they are, they are dreaming of Finals from last year's President's Cup. To escape their dream space, you'll need to break into a recreation of the challenge site hosted at `http://pccc.pccc` and steal each of their totems (which, given their obsession with producing great challenges, take the form of challenge tokens).

## Getting Started

Use the provided Kali device to access the vulnerable President's Cup site at `http://pccc.pccc`.

## Tokens

There are four tokens to retrieve. The tokens are formatted as `PCCC{some_words_here}`.

No grading is required; all tokens are found in the environment.

- Token 1: The first developer is dreaming of providing support. Gain access to a support account to find the token.
- Token 2: The second developer is dreaming of becoming an admin. Gain access to an admin account to find the token.
    - You may need to log out and back in to display the token.
- Token 3: The third developer is dreaming about the infrastructure. Find this token in `/app/token.txt`.
- Token 4: The fourth developer is dreaming about the logs. Send the message `GIVEMETHETOKEN` to `/app/log.txt`, and the developer will add the token to the home page.

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-vnc|user|password|