# No Language Is Perfect Vol. II: More Fun With Numbers

Identify a flaw given some source code, and then exploit the flaw.

**NICE Work Role:**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:**

- [T0111](https://niccs.cisa.gov/workforce-development/nice-framework) - Identify basic common coding flaws at a high level.
- [T0176](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities.

## Background

This challenge was heavily inspired by a challenge from PresCup season 1. This version adds a big twist and adds information to the given source code indicating where the original had a flaw, in order to minimize first-year competitors' advantage. The server has been modified in several important ways, for the player to discover.

## Getting Started

Analyze [oldsource.rs](challenge/oldsource.rs) and find the comment block indicating where the original flaw was located. It will also be helpful to examine [gameclient.py](challenge/gameclient.py) in order to learn how a client can interact with the server. Find a flaw in this new version of the server, and retrieve the challenge flag.
