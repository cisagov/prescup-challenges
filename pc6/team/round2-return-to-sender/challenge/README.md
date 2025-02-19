# Challenge Artifacts

- ``myGradingScript.sh`` - The grading script runs three checks:
	- Check 1: ``ssh``'s as ``user`` and checks if the user **`notme`** exists and, if so, searches their **crontab** for any `cp` (copy) commands.
	- Check 2: ``ssh``'s as ``user``and checks if port `4444` is open and listening.
	- Check 3: ``ssh``'s as ``user`` and searches for `malicious_file` in `/home/user/Desktop/` and confirms its existence.