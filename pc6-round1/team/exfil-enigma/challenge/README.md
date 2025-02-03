# Exfil Enigma

*Challenge Artifacts*

- `Databases`:
  - Database files for each of the four variants
    - [users1.db](./databases/users1.db)
    - [users2.db](./databases/users2.db)
    - [users3.db](./databases/users3.db)
    - [users4.db](./databases/users4.db)

- `db-server`:
   - [db-post.sh](./db-server/db-post.sh) - Bash script that repeatedly posts the database file to a remote web server.
   - [db.service](./db-server/db.service) - The service file that runs `db-post.sh`.
   - [web-request.sh](./db-server/web-request.sh) - Bash script that repeatedly makes HTTP GET requests while sending Token 4 in as a base64 encoded string in the Session header.
   - [webrequest.service](./db-server/webrequest.service) - The service file that runs `web-request.sh`.

- `web-server`:
   - [keyfile.txt](./web-server/keyfile.txt) - The text file that is downloaded by the SecurityService application that is used to encrypt files with `gpg`.
   - [about.html](./web-server/about.html) - About page of the suspicious data exfiltration target machine.
   - [faq.html](./web-server/faq.html) - FAQ page of the suspicious data exfiltration target machine.
   - [fileupload.html](./web-server/fileupload.html) - File upload page of the suspicious data exfiltration target machine. This is the target for the database POST.
   - [home.html](./web-server/home.html) - Home page of the suspicious data exfiltration target machine.
   - [index.html](./web-server/index.html) - Default page of the suspicious data exfiltration target machine.

- `user-workstation`:
   - [Budget%20Proposal.odt.gpg](./user-workstation/Budget%20Proposal.odt.gpg) - Encrypted document
   - [Employee%20Payroll%20Summary.odt.gpg](./user-workstation/Employee%20Payroll%20Summary.odt.gpg) - Encrypted document
   - [Internal%20Expense%20Report.odt.gpg](./user-workstation/Internal%20Expense%20Report.odt.gpg) - Encrypted document
   - [Invoice.odt.gpg](./user-workstation/Invoice.odt.gpg) - Encrypted document
   - [Quarterly%20Financial%20Summary.odt.gpg](./user-workstation/Quarterly%20Financial%20Summary.odt.gpg) - Encrypted document
   - [securityservice.service](./user-workstation/securityservice.service) - The service file that starts the `SecurityService` .NET console application.
   - [SecurityService](./user-workstation/SecurityService/)
     - To build this application you must have the .NET 6 Framework and .NET developer tools installed on your machine.
     - Go to the [SecurityService](./user-workstation//SecurityService/) folder and run the following commands:

```bash
dotnet build --configuration Release
dotnet publish --configuration Release
```

  - You must then deploy the contents of the `bin\Release\net6.0\publish` folder to the appropriate folder on your VM.

- `wan-1`:
  - [netcatlistener.sh](./wan-1/netcatlistener.sh)

- `exfil-machine`:
  - Scripts used by the exfiltration service
