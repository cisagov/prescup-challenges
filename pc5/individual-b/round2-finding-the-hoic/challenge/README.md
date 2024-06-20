# Finding the HOIC

_Challenge Artifacts_

- [Hacker Forum Chat Web Site](./HackerForumChatWebSite/) - This is the source code for that static web site that displays the hacker chat forum.
   - This is a static web site consisting of .html and .css files and does not need to be compiled to be used. 

- [HOIC Web Site](./HOICWeb/) - This is the source code for the ASP.NET web site that users must perform a password spraying attack against then find and download the HOIC.zip file.
   - Compile this C# ASP.NET Core web site using the following command: `dotnet build` 

There are four instances of the HOIC web site, but only one is active based on the variant that gets deployed. Below are the details for each instance.

1. URL: `http://ocie.biz`
IP: 10.7.7.241

2. URL: `http://wilfrid.net`
IP: 10.7.7.199

3. URL: `http://trent.biz`
IP: 10.7.7.150

4. URL: `http://talon.biz`
IP: 10.7.7.111

- [HOIC Console Application](./hoic/) - This is the source code for the HOIC console application that users must retrieve from the HOIC.zip file, then interact with to answer the final two questions.
   - Compile this C# .NET console application for Linux using the following command: `dotnet publish --runtime linux-x64 --configuration Release /p:PublishSingleFile=true /p:PublishTrimmed=true`

- [passwords.txt](./passwords.txt) - This file is used with the harvested email addresses to perform a password spraying attack.
- [wordlist.txt](./wordlist.txt) - This file is used to crack the HOIC.zip file password. 
