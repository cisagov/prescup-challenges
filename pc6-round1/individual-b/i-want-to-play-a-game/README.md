# I Want to Play a Game

Help a small game company perform security testing against one of their APIs.

**NICE Work Role**

- [Cyberspace Operations](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**

- [T1669](https://niccs.cisa.gov/workforce-development/nice-framework/): Analyze system vulnerabilities within a network
- [T1691](https://niccs.cisa.gov/workforce-development/nice-framework/): Detect exploits against targeted networks and hosts
- [T1734](https://niccs.cisa.gov/workforce-development/nice-framework/): Exploit network devices and terminals

## Background

Use the provided tools and resources to analyze and exploit the game API.

## Getting Started

Login to the `kali-play-game` VM.  The `wordlists.txt` file is mounted as a drive and is visible on the Desktop. You've also been given some additional information by the game API developers.

**Web API details:**

 - The web API is located at: `http://10.7.7.200/swagger/index.html`.
 - To call API methods other than `Login`, include the `UserAuthToken` HTTP header with a valid token value.
 - A successful call to the `Login` method returns the value needed to pass in the `UserAuthToken` header.
 - Login to the API with the following credentials: **Username:** `tstewart`| **Password:** `linkinpark`.

**Postgres Database details:**

 - The Postgres database server is on the `10.1.1.0/24` subnet.
 - The Postgres database server account is: `postgres`.

If you use **Security Onion** to create PCAP files, make sure to enter `securityonion` in the `Sensor ID` field. Log into Security Onion at `10.4.4.4` through a browser or via SSH.

## Submission Hints

There are four (4) tokens to retrieve in this challenge.

- **Question 1 Hint:** Crack the existing `postgres` database account password.
- **Question 2 Hint:** Crack the MD5 hash of the `game_server_admin` account password stored in the user database to retrieve the token.
- **Question 3 Hint:** Use the GameAPI to defeat the Silver Dragon enemy character. First, call the `Login` method to obtain the `UserAuthToken`. Use this token to call other API methods and attack the Silver Dragon. If successful, the `Attack` method will provide the token. Note that you ***cannot*** modify the Silver Dragon's health through the database. The API detects tampering and resets the enemy's health.
- **Question 4 Hint:** Exploit a vulnerability in the `ReadFileContents` API method to retrieve the contents of the `token4.txt` file. The file's contents are the token for this question.

## Challenge Questions

1. What is the password of the postgres account on the postgres database server?
2. What is the password of the game_server_admin account in the Users table of the GameAPI database? You will need to crack the hashed password to get the correct answer.
3. What is the token presented in the API response after using the GameAPI to attack and defeat the Silver Dragon enemy character?
4. What is the value of token4, which can be found by exploiting the ReadFileContents API method to retrieve the contents of the token4.txt file?