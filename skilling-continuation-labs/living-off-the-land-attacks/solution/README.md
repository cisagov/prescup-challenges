# Living Off The Land

## Mini-challenge Solution Guide

1. (**Attack-Console**, **Terminal**) Use SSH to connect to the `Mini-Challenge` server with the command `ssh user@mini-challenge`. If asked if you want to continue connecting, type `yes` and press Enter.

2. (**Attack-Console**, **Terminal**) Enter the password `tartans` and press Enter to connect.

3. (**Attack-Console**, **SSH Session**) Create a new rules file called `powershell.rules` with the command `sudo nano /etc/audit/rules.d/powershell.rules`. If prompted, enter the `sudo` password `tartans` and press Enter.

4. (**Attack-Console**, **SSH Session**, **Nano Editor**) Create a rule to audit the execution of the PowerShell binary by entering the following rule:

```rules
-a always,exit -F arch=b64 -S execve -F path=/opt/microsoft/powershell/7/pwsh -F key=powershell_exec
```

5. (**Attack-Console**, **SSH Session**, **Nano Editor**) Write out (save) your changes in Nano by pressing Ctrl+o.

6. (**Attack-Console**, **SSH Session**, **Nano Editor**) Confirm the filename by pressing Enter

7. (**Attack-Console**, **SSH Session**, **Nano Editor**) Exit Nano by pressing Ctrl+x.

8. (**Attack-Console**, **SSH Session**) Add the `powershell.rules` to the main rules file with the command `sudo augenrules --load`

> Allow a few minutes for the commands to be captured

9. (**Attack-Console**, **SSH Session**) Search the audit logs for the key `powershell_exec` with the command:

```bash
sudo ausearch -k powershell_exec
```

10. (**Attack-Console**, **SSH Session**, **Audit Logs**) Highlight and copy the Base64 command to your clipboard.

(**Attack-Console**) Open FireFox.

(**Attack-Console**, **FireFox**) Click on CyberChef from the Bookmarks Toolbar.

(**Attack-Console**, **FireFox**, **CyberChef**) In the upper-right "Input" box, paste the encoded command from the log file.

(**Attack-Console**, **FireFox**, **CyberChef**) In the Operations pane (on the left), drag "From Base64" to the Recipe box.

(**Attack-Console**, **FireFox**, **CyberChef**) In the Operations pane's search field, search for "null".

(**Attack-Console**, **FireFox**, **CyberChef**) In the Operations pane, drag "Remove null bytes" to the recipe box.

(**Attack-Console**, **FireFox**, **CyberChef**) With the Recipe built, examine the "Output" box. This is the decoded command.
