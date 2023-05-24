# WordPress Pirates


Utilize exploitation to gain access to a web server suspected of criminal activity.


**NICE Work Roles:**
* [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework)

**NICE Tasks:** 
* [T0570](https://niccs.cisa.gov/workforce-development/nice-framework) - Apply and utilize authorized cyber capabilities to enable access to targeted networks.
* [T0591](https://niccs.cisa.gov/workforce-development/nice-framework) - Perform analysis for target infrastructure exploitation activities.

## Note
There are no artifacts available for this challenge and it must be completed in the hosted environment.

## Background
We have discovered a wordpress site hosting pirated movies masquerading as a movie review site. Using the Kali machine and provided exploitation scripts, you should access the Wordpress site being hosted at `legit-movies.us` and find the pirated content. We have a theory that the site might be vulnerable to an exploit due to an insecure plugin. If possible, we would like you to gain access to the machine that is hosting the site in order to investigate the illegal pirating operation.

  ## Getting Started

  Navigate to the URL http://legit-movies.us, find the pirated content and exploit the server.

  You have been provided with the following resources (additional to base Kali linux tools) to aid you:

  1) A directory (`/home/user/Desktop/Exploits`) containing various exploits that may be helpful
  2) A wordlist (`/usr/share/wordlists/utah-wordlist.txt`) of passwords that utah may be using

  ## Submission Format

  There are four (4) questions with randomized answers. Their formats are as follows:

  1) A movie title
  2) A 16-character hexadecimal string
  3) A 16-character hexadecimal string
  4) A 16-byte Base64 hash
