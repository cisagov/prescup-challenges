
# Now You're Thinking with Portals

_Setup_

1. Create an Ubuntu Linux machine. This example assumes a static IP address of `10.5.5.140`.  
2. [Install the Apache Web Server](https://ubuntu.com/tutorials/install-and-configure-apache#1-overview) on the Ubuntu machine.  
3. [Install PostgreSQL](https://ubuntu.com/server/docs/databases-postgresql). You can choose to install PostgreSQL on this Ubuntu machine or use a separate Ubuntu Linux machine.  
4. [Install the .NET Runtime](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu) on the web server.  
5. [Build](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/aspnetcore/practice-troubleshoot-linux/2-1-create-configure-aspnet-core-applications) the TransportManagementPortal and TMPAdminAPI web applications on the web server.   
Navigate to the root of the TransportManagementPortal directory and run the following commands:  `dotnet build`  
Navigate to the root of the TMPAdminAPI directory and run the following command: `dotnet build`  
6. Deploy the TransportManagementPortal application to the web server at `/var/www/html/tmp`.  
7. Deploy the TMPAdminAPI application to the web server at `/var/www/html/tmpadminapi`.  
8. Copy the [setup.sh](setup.sh) script to your web server and run it to copy the tokens to the default Apache folder `/var/www/html`.  

## web server
### TransportManagementPortal
This C# .NET (.NET 6.0) project, using is a web application that runs on the Ubuntu web server. Challenge competitors must interact with it to retrieve tokens 1 - 4. All required source code has been included in the [TransportManagementPortal](TransportManagementPortal) folder. It can be built and deployed using compatible tools such Visual Studio or Visual Studio Code as well .NET command line tools such as `dotnet`. You ust configure the [connection string](TransportManagementPortal/appsettings.json) settings to match your database installation.  

### TMPAdminAPI
This C# .NET project is a web based API that runs on the Ubuntu web server. Challenge competitors must interact with it to retrieve token 5. All required source code has been included in the [TMPAdminAPI](TMPAdminAPI) folder. It can be built and deployed using compatible tools such Visual Studio or Visual Studio Code as well .NET command line tools such as `dotnet`. You ust configure the [connection string](TMPAdminAPI/appsettings.json) settings to match your database installation.  

## database
This is an Ubuntu server that runs a PostgreSQL database server. This server hosts the prescup4_TransportManagementPortal_db application database that is accessed by the TransportManagementPortal and TMPAdminAPI web applications. The database is created and populated with data by the [DbInitializer.cs](TransportManagementPortal/Data/DbInitializer.cs) code in the TransportManagementPortal project. Before this script can be executed, you must install and configure PostgreSQL and create the appropriate accounts referenced in the [appsettings.json](TransportManagementPortal/appsettings.json) file in the TransportManagementPortal project. 
