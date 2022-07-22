
# Something Is Awful

Analyze code for a message board to find and fix vulnerabilities.

**NICE Work Roles:**   

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)
- [Cyber Defense Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Cyber+Defense+Analyst&id=All)


**NICE Tasks:**

- [T0591](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0591&description=All) - Perform analysis for target infrastructure exploitation activities.
- [T0694](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0695&description=All) - Examine intercept-related metadata and content with an understanding of targeting significance.


## Background  

You have been hired to perform a security audit of a startup company hosting a message board platform, named awfulbb. Unfortunately for them, they opted for the low-priced development option. The system is riddled with security issues and your job is to fix them. The message board allows users to register, post threads, and reply to threads. It is currently a "minimum viable product" and lacks features that more sophisticated platforms incorporate. The bright side is that the codebase is relatively small and bugs should be easy to find and fix.

The message board site files are located in the [awfulbb folder](challenge/awfulbb) and will launch on port 5000 by running the [wsgi.py](challenge/awfulbb/wsgi.py) python script.  You will need to find and fix any vulnerabilities in the site while ensuring core functionality is retained.


## Getting Started
In a fresh Ubuntu VM, place these challenge files in the same directory.

Open a terminal window in the directory and run:

```bash
sudo sh ./install.sh
```

As you make code changes to the [provided web server](challenge/awfulbb), you will need to start, stop, and restart the web service. Starting the web service can be accomplished by:

```bash
sudo python3 ./awfulbb/wsgi.py
```

 To stop, simply Ctrl-c in the terminal running wsgi.py
 

## Grading Challenge
You can score your progress by running the following script from the terminal in the directory:

```bash
sudo python3 grade-challenge.py
```

This will output 4 checks with an indication of success or failure.

The grading service checks for core functionality as well as whether the vulnerabilities have been mitigated or not. The solution tokens will be displayed by the grading service as the vulnerabilities are eliminated. Note that core functionality must remain intact in order to earn the full solution.



## Note
The grading checks are looking for 3 specific vulnerabilities. There may be other vulnerabilities in this web application that are not part of the scoring of this challenge. 

