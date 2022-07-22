# Pwning PowerShell

Leverage PowerShell (and an offensive security framework designed to exploit PowerShell functionality) to conduct post-exploitation related tasks on Windows 10 hosts.

**NICE Work Role:** 

- [Exploitation Analyst](https://niccs.cisa.gov/workforce-development/nice-framework/workroles?name=Exploitation+Analyst&id=All)

**NICE Tasks:**

- [T0028](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0028&description=All) - Conduct and/or support authorized penetration testing on enterprise network assets.

- [T0266](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0266&description=All) - Perform penetration testing as required for new or updated applications.

- [T0570](https://niccs.cisa.gov/workforce-development/nice-framework/tasks?id=T0570&description=All) - Apply and utilize authorized cyber capabilities to enable access to targeted networks.  

## IMPORTANT
This challenge is only partially open sourced. The files in the challenge directory are provided to give a starting point if you want to recreate the challenge on your own. The full challenge can be completed on the hosted site.

## Background

PowerShell is a powerful task-based command line shell and scripting language that allows for the rapid automation and execution of tasks that manage operating systems and processes. Multiple offensive security frameworks exist that are specifically designed to exploit PowerShell's ability to perform a wide range of administrative tasks. One such framework is **PowerSploit**. You must utilize the built-in scripts and modules of PowerSploit to obtain six total tokens spread across four different Windows 10 hosts.

## Getting Started

There are four Windows 10 hosts, three of which you have desktop access to. Use the following instructions/system information to obtain as many tokens as you can! 

*Hint: don't forget about PowerShell's built-in `Get-Help` cmdlet.*

## ScriptMod

Important System Information:
- 2 tokens (5% each)
- User-level privileges by default
- Windows Defender disabled
- PowerSploit module preinstalled at `C:\\ProgramFiles\\WindowsPowerShell\\Modules\\PowerSploit`

There are two files located in the  `C:\\Users\\flare\\Documents` directory : 
- [encoded-script.txt](challenge/encoded-script.txt)
- [encrypted-script.ps1](challenge/encrypted-script.ps1)

When properly utilized, each file will produce a token. Starting with [encoded-script.txt](challenge/encoded-script.txt), use PowerSploit cmdlets or any other known means to print each token to the console. Pay special attention to the VM name to help you determine a starting point.

## PrivEsc

Important System Information:
- 1 token (25%)
- User-level privileges by default
- Windows Defender disabled
- PowerSploit module preinstalled at `C:\\Program Files\\WindowsPowerShell\\Modules\\PowerSploit`

There is a permission-restricted file located at `C:\\Users\\admin\\Documents\\privesc-token.txt`. Use PowerSploit cmdlets or any other known means to escalate your privileges and view the contents of the file. Pay special attention to the VM name to help you determine a starting point. 

*Hint: you may come across `w1bscntrl.dll`as a possible privilege escalation vector; it is recommended that you explore other possibilities.*

## CodeExec

Important System Information:
- 1 token (25%)
- User-level privileges by default
- Windows Defender **enabled**
- PowerSploit module preinstalled at `C:\\Program Files\\WindowsPowerShell\\Modules\\PowerSploit`

There is file located at `C:\\Users\\flare\\Documents\\`[shellcode.txt](challenge/shellcode.txt) that contains a PowerShell payload. Use PowerSploit cmdlets or any other known means to execute the payload and print the token to the console. Pay special attention to the VM name to help you determine a starting point. 

*Hint: don't forget that Windows Defender/AMSI is still enabled.*

## Hidden

Important System Information:
- 2 tokens (5% and 35% respectively)
- Admin-level privileges by default
- Windows Defender **enabled**
- PowerSploit module **not** available locally 

The final machine is hidden from viewing. You must utilize PowerSploit or other known means to find and log on to the machine. The first simple token can be viewed at `C:\\Users\\flare\\Documents\\hidden-token.txt`. For the final token submission, find the NTLM hash of the user, ***Scotty***.

*Hints:* 

- *Don't forget that Windows Defender/AMSI is still enabled.*
- *All competition machines have Python preinstalled. Python has a lightweight HTTP server built-in.*

## Submission Format

Each system contains 1-2 tokens of varying weights. If you correctly execute the given task(s) on that system, the tokens will be printed to the console or viewable by other means.

The first five tokens are 16-digit hexadecimal numbers wrapped in the standard President's Cup wrapper of the format `prescup{0123456789abcdef}`.

The final and most heavily weighted submission is in the format of an NTLM hash of a specified user.

Please ensure that you supply each token in the correct box as labeled.
