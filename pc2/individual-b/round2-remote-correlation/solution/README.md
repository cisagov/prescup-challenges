# Remote Correlation Solution

### Section 1 - Intel Gathering

Reading the provided incident report should lead the challenger to look for the following artifacts along with the knowledge of editing firewall, scheduled tasks, registry, and WMI:

1. Use of port 4444

2. File hash FF79D3C4A0B7EB191783C323AB8363EBD1FD10BE58D8BCC96B07067743CA81D5

3. Registry location HKLM:\Software\Microsoft\Windows\CurrentVersion\Run

4. Changing Powershell execution policy 

### Section 2 - Remote Access

In order to interact with the remote machines in this challenge, we can use PsExec. PsExec is a program included in the Microsoft SysInternals Suite that allows commands and other programs to be executed on remote systems. 

To start a Powershell console on the remote computer called `eeny` you can use the following PsExec command:
`PsExec.exe \\eeny -u eeny\user -p tartans powershell.exe`

In this command `\\eeny` is the remote computer. `-u eeny\user` indicates that we want to use the local 'user' account on the machine `eeny`. `-p tartans` is the password for the user. And `powershell.exe` is the program we want to run on the remote machine. 

The below screenshot shows what this command looks like when it is run. The second shell prompt is a Powershell session on the machine `eeny`.

   <img src="img/image1.PNG">  


This process can be repeated to gain remote access to each of the remote systems.


### Section 3 - Firewall Rules

After you gain access to one of the remote machines, you can start by looking for the malicious firewall rules. There are several commands to accomplish this. 

`Get-NetFirewallRules -Enabled True` - This command will show all of the enabled firewall rules on the system. An optional part of the command is: ` | Format-Table` which will display the rules listed in a table format.  

Recently added user-rules will appear at the bottom of the table. Notice that one rule, named `rule`, will look different than the others. We can observe this rule further with the following command: `Get-NetFirewallRule -Name rule`. This shows more details about the rule. 

Also use the command `Get-NetFirewallRule -Enabled True | Get-NetFirewallPortFilter | Format-Table`, to view rules which filter nby port.

On some of the machines in the environment, there will be a rule configured to allow TCP Port 4444. This is consistent with the intel gathered from the incident report. The machines which have this rule configured should be noted for the answer. 


### Section 4 - Scheduled Tasks

We can also look for scheduled task via powershell. Use the following command to view scheduled tasks: `Get-ScheduledTask`.  On some of the machines, you will notice a task called `task`.     

View more about this task with the following command:  `Get-ScheduledTask -TaskName task | Export-ScheduledTask`. This command will show a detailed view of the task in XLM format. One important thing to note is the task action. Notice the task action is an encoded Powershell command. We can decode this command to see what commands are being run. 

To decode the encoded powershell string, use the following command `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Insert_encoded_string_here>"))`

The malicious scheduled task commands will decode to a command for a netcat listener on port 4444. The use of port 4444 is consistent with the indicators of compromise from the incident report. The malicious ended string is `bgBjACAALQBsACAALQBwACAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAgAC0AZAA=`.

The machines with this entry should be noted for the answer. 


### Section 5 - Registry Entries

Powershell can be used to query registry entries as well. Use the following command to view items in the registry location gathered from the incident report: `Get-Item -Path Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run` .  This may show results similar to those shown in the screenshot below.   

   <img src="img/image2.PNG">  

Notice that these entries are starting programs at system startup. Based on the gathered intelligence, we are aware of a file hash. We can check these autorun programs to see if the file hash matches the known hash of FF79D3C4A0B7EB191783C323AB8363EBD1FD10BE58D8BCC96B07067743CA81D5, by using the command `Get-FileHash "<Insert_file_path_here>"`. The output of this command should look like the screenshot below.

   <img src="img/image3.PNG">  

The program `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\prog.exe` should have the same file hash as the one listed in the incident report. The machines with this malicious entry should be noted for the answer. 


### Section 5 - WMI Entries

WMI Entries can be queried with Powershell as well. Querying for the desired malicious entries in the root\subscription WMI namepsace will also require a bit of insight to know that the class of objects to look for should be `__FilterToConsumerBinding` which allows a desired action to be triggered by an event. 

The fastest way to find any entries we want to look for will be to run the following command: `Get-WMIObject -namespace root\subscription -class __FilterToConsumerBinding`. This command will show objects which tie an event to an action that is to be performed. 

   <img src="img/image4.PNG">  

Notice in the above screenshot the object which connects the `sub` event filter to the `con` CommandLineEventConsumer. Gather more information about the CommandLineEventConsumer with the following command: `Get-WMIObject -namespace root\subscription -class CommandLineEventConsumer`.

   <img src="img/image5.PNG">  

In the above image, you can see the command that is triggered with this consumer. Decode the shown command in the same way as in Section 4.  The malicious encoded and decoded commands are below:  
Encoded: `UwBlAHQALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAFUAbgByAGUAcwB0AHIAaQBjAHQAZQBkAA==`

Decoded: `Set-ExecutionPolicy Unrestricted`

This command follows the activity pattern from the incident report. The machines with this malicious entry should be noted for the answer. 

### Submission

The submission should be the computer names with the malicious entries (entered in alphabetical order and separated by a space)

#### Version 1

1. Malicious Firewall Entries - eeny, miney
1. Malicious Scheduled Tasks  - meany, miney
1. Malicious Registry Entries - meany
1. Malicious WMI Entries      - eeny, meany

#### Version 2

1. Malicious Firewall Entries - meany, miney
1. Malicious Scheduled Tasks  - eeny, meany
1. Malicious Registry Entries - eeny
1. Malicious WMI Entries      - eeny, miney

#### Version 3

1. Malicious Firewall Entries - meany, miney
1. Malicious Scheduled Tasks  - eeny, meany
1. Malicious Registry Entries - meany
1. Malicious WMI Entries      - eeny, miney

#### Version 4

1. Malicious Firewall Entries - eeny, meany
1. Malicious Scheduled Tasks  - eeny, miney
1. Malicious Registry Entries - eeny
1. Malicious WMI Entries      - meany, miney

