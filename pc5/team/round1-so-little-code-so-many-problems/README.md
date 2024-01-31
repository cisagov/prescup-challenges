# So Little Code, So Many Problems

Multiple bugs and vulnerabilities have been identified in our C# .NET Web API application. Fix the code and configure the API application according to the accompanying bug report. 

**NICE Work Roles**

- [Software Developer](https://niccs.cisa.gov/workforce-development/nice-framework/)

**NICE Tasks**
- [T0046](https://niccs.cisa.gov/workforce-development/nice-framework/): Correct errors by making appropriate changes and rechecking the program to ensure that desired results are produced.  
- [T0176](https://niccs.cisa.gov/workforce-development/nice-framework/): Perform secure programming and identify potential flaws in codes to mitigate vulnerabilities.  
- [T0553](https://niccs.cisa.gov/workforce-development/nice-framework/): Apply cybersecurity functions (e.g., encryption, access control, and identity management) to reduce exploitation opportunities.

<!-- cut -->

## Background

Use the provided kali workstations, developer guide, and bug report to make code changes to the Web API application.

## Getting Started

> **Caution!** Do not make any modifications to the API code that are not specified in the bug report. This includes changes to method names, routes, returned values, data types or formats for any of the methods, etc. Unspecified changes may disrupt grading.

Log into the `kali` VM. The Developer Guide and Bug Report are available on the Desktop. Visual Studio Code and the .NET Framework have been installed on the `kali` VMs.

The inventory web application and API web application are available inside the challenge environment at `http://inventory.merch.codes` and `http://api.merch.codes`. 

The *Developer Guide* and *Bug Report* tell you what issues to fix, how to access the source code, and how to build and deploy the applications.

## Submissions

There are four (4) tokens to retrieve in this challenge. Each of the tokens are twelve (12) character hexadecimal strings. Notes on each token are provided below.

**Question 1:** Update the `SearchInventory` method of the `InventoryController` class to prevent an SQL injection attack. The updated method must return inventory items when searched for by name, but can't return results as a consequence of injected SQL statements.

**Question 2:** Update the `GetFiles` method of the `FilesController` class to prevent unauthenticated API calls from retrieving files. The method should return a `Json(Unauthorized())` result if a call to `IsUserAuthenticated()` returns false.

**Question 3:** Update the `UploadFile` method of the `FilesController` class to return a `Json(false)` result if either of the following conditions are true:

- The uploaded file length is larger than 1,000,000 bytes
- The file extension of the uploaded file is .exe 

**Question 4:** Update the `GetInventoryItems` method of the `InventoryController` class to return HTML-encoded `Name` and `Description` fields.

Make the changes described above then refer to the *Developer Guide* to build and deploy the application to the **api-db-server**.  

In the gamespace, browse to `https://challenge.us` and run the validation script. You can run the validation script as many times as needed while you make the required application changes. You will be given a token for each of the four updates described above.  

## System and Tool Credentials

| system/tool                | username  | password |
|----------------------------|-----------|----------|
| kali                       | user      | tartans  |
| web-server                 | user      | tartans  |
| api-db-server              | user      | tartans  |

## Note

Attacking or unauthorized access to `challenge.us` (10.5.5.5) is forbidden. You may only use the provided web page to view challenge progress and download any challenge artifacts that are provided.

## Challenge Tasks

1. Enter the SQL injection vulnerability token.
2. Enter the authenticated access to files endpoint token.
3. Enter the file upload validation token.
4. Enter the XSS vulnerability token.
