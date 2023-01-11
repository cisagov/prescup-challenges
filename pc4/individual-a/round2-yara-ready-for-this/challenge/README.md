# Yara Ready For This

_Setup_

These setup steps will allow you to solve _most_ of this challenge offline. You will not be able to solve Question 7 offline.

1. Run the [setup.sh](./setup.sh) script to generate additional challenge resources
1. Create a Ubuntu VM that will act as the malicious web server with 2 IP addresses: `10.5.5.173` and `10.5.5.235`
1. Copy the contents of the [malicious-web-server](./malicious-web-server/) directory to your Ubuntu VM. From that directory on the VM, run the following command to start a web server: 
```bash
sudo python3 -m http.server 80
```
1. Copy the contents of the [listeners](./listeners/) directory to your Ubuntu VM. From that directory, run the following command to start all of the listeners: 
```bash
sudo ./start-all-listeners.sh
```
1. Create a Windows 10 VM and [install dotnet core](https://dotnet.microsoft.com/en-us/download). 
1. Copy the contents of the [ADSVCEXEC](./ADSVCEXEC/) directory to the Windows 10 VM. This directory is the "ISO" that the challenge instructions reference. 