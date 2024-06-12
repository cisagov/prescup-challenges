# So Little Code, So Many Problems

_Challenge Artifacts_

- [MerchCodesInventoryApi](./MerchCodesInventoryApi) -- This is the source code for the vulnerable web API.
    - compile this C# ASP.NET Core Web API using the instructions included in the [Developer Guide](./Developer%20Guide.txt)

- [MerchCodesUI](./MerchCodesUI) -- This is the source code for the UI web application.
    - compile this C# ASP.NET Core Web API using the instructions included in the [Developer Guide](./Developer%20Guide.txt)
    - Use this command: `dotnet ef database update` from the terminal of Visual Studio code to create the database for the web application. 

- [gradingScript.py](./gradingScript.py) -- This grading script runs to grade the environment when the challenge is deployed in the hosted environment. It may not operate as intended unless it is run with a VM configuration that mirrors what is in the hosted challenge.
    


