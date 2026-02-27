# Second-Order Pawn

Your team has been monitoring a known spy, and they are finally making their move. They plan to smuggle a laptop with state secrets through an online pawn shop called "Second-Order Pawn and Auction". Exploit the site and prevent the hand-off.

**NICE Work Roles**

- [Vulnerability Analysis](https://niccs.cisa.gov/tools/nice-framework)
- [Exploitation Analysis](https://niccs.cisa.gov/tools/nice-framework)

**NICE Tasks**

- [T1359](https://niccs.cisa.gov/tools/nice-framework): Perform penetration testing
- [T1118](https://niccs.cisa.gov/tools/nice-framework): Identify vulnerabilities

## Background

Your team has been monitoring a potential insider threat operating in the government. As the spy is unaware of your monitoring, you've allowed them to continue their operations in the hope of identifying other threats. However, the spy has recently gotten their hands on a sensitive laptop which must be retrieved. Their plan is to use the "Second-Order Pawn and Auction Shop" (`http://pawn.secondorder.pccc`) as an intermediary by selling the laptop in a "legit" transaction. If we bust down the doors and confiscate the laptop, the other threat won't reveal themselves. Therefore, your team has been granted permission to hack into the pawn shop and discreetly prevent the sale. 

## Getting Started

Use the provided Kali machine to access the Second-Order Pawn sites: `http://pawn.secondorder.pccc`, which manages all aspects of the pawn and auctions, and `http://warehouse.secondorder.pccc`, which manages item drop-offs, pick-ups, and shipping. 

## Tokens

There are four tokens to retrieve. The tokens are formatted as `PCCC{some_words_here}`.

No grading is required.

- Token 1: We need more intel; leak the web application source code.
    - The token will be in a comment in `app.py`. Pay special attention to where the site interacts with files.
- Token 2: Compromise the database and find this token in the description of an unpublished auction item named `Token`.
- Token 3: Your successful database exfiltration has revealed the Pawn and Warehouse databases are separated; you'll need to find a different way to get the admin to approve your auction cancellation request.
    - The admin checks for and denies any cancellation request every 10-20 seconds. The token will be provided once any cancellation request has been approved.
- Token 4: The spy has arrived at the warehouse for the drop-off. Hijack their session so they create the auction under your account, which we can forcibly cancel later.
    - The spy seems nervous for the hand-off; our monitoring shows he is mindlessly refreshing the RSS feed and reviewing any *new* items added to the list. The token will be in the item description after you compromise their session.
    - Similar to Token 3, the spy does this every 10-20 seconds.  

## System and Tool Credentials

|system/tool|username|password|
|-----------|--------|--------|
|kali-vnc|user|password|
