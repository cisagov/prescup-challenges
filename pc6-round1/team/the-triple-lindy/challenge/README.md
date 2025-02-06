# The Triple Lindy

*Challenge Artifacts*

- `kali-modbus-server-triple-lindy`:
  - These python scripts simulate a SCADA server that provides data to the pool web site's `Pool Conditions` web page.
  - [poolserver.py](./challenge/kali-modbus-server-triple-lindy/poolserver.py)
  - [poolclient.py](./challenge/kali-modbus-server-triple-lindy/poolclient.py)

  - These service configuration files start the python scripts for the SCADA client and server.
  - [poolserver.service](./challenge/kali-modbus-server-triple-lindy/poolserver.service)
  - [poolclient.service](./challenge/kali-modbus-server-triple-lindy/poolclient.service)

- `kali-pool-triple-lindy`:
  - [kestrel-pool.service](./challenge/kali-pool-triple-lindy/kestrel-pool.service) - This service runs the .NET pool web site.
  - [pool](./challenge/kali-pool-triple-lindy/pool/) - This is the source code for the .NET web pool web site.

  - To build this application you must have the .NET 6 Framework and .NET developer tools installed on your machine.
  - Go to the [pool](./challenge/kali-pool-triple-lindy/pool/) folder and run the following commands:

```bash
dotnet build --configuration Release
dotnet publish --configuration Release
```

  - You must then deploy the contents of the `bin\Release\net6.0\publish` folder to the appropriate folder on your web server.

- `kali-pool-sec-api-triple-lindy`:
  - [kestrel-secapi.service](./challenge/kali-pool-sec-api-triple-lindy/kestrel-secapi.service) - This service runs the .NET API web application.
  - [SecurityApi](./challenge/kali-pool-sec-api-triple-lindy/SecurityApi) - This is the source code for the .NET web API.

  - To build this application you must have the .NET 6 Framework and .NET developer tools installed on your machine.
  - Go to the [SecurityApi](./challenge/kali-pool-sec-api-triple-lindy/SecurityApi) folder and run the following commands:

```bash
dotnet build --configuration Release
dotnet publish --configuration Release
```

 - You must then deploy the contents of the `bin\Release\net6.0\publish` folder to the appropriate folder on your web server.

- `kali-pool-vendor-web-triple-lindy`:
  - [kestrel-vendor.service](./challenge/kali-pool-vendor-web-triple-lindy/kestrel-vendor.service) - This service runs the .NET third party Automated Pool Management web site.
  - [vendor](./challenge/kali-pool-vendor-web-triple-lindy/vendor/) - This is the source code for the .NET third party Automated Pool Management web site.

 - To build this application you must have the .NET 6 Framework and .NET developer tools installed on your machine.
 - Go to the [vendor](./challenge/kali-pool-vendor-web-triple-lindy/vendor/) folder and run the following commands:

```bash
dotnet build --configuration Release
dotnet publish --configuration Release
```

 - You must then deploy the contents of the `bin\Release\net6.0\publish` folder to the appropriate folder on your web server.