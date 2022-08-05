# President's Cup Season 4: Virtual Machine Builds

## Summary

President's Cup Season 4 includes many virtual machines as a part of the challenges. This directory contains Packer build instructions to create the competitor VMs for review. The install scripts also provide the tools installed on top of each base operating system.

There are two competitor virtual machines provided&mdash;Kali and Windows 10&mdash;and more builds will be released over time.

## Build Instructions

1. Install [Packer](https://www.packer.io/).
2. Install [VirtualBox](https://www.virtualbox.org/).
3. Download this repository and change into the directory of the build:
    ```
    cd [kali|win10]
    ```
4. Run the Packer build command against the `.pkr.hcl` file in that directory:
    ```
    packer build [kali|win10].pkr.hcl
    ```
5. Wait for the build to complete (it can take several hours).

## User Credentials

Here are the default user accounts for each virtual machine:

| OS | Username | Password |
| -- | -------- | -------- |
| Kali Linux | `user` | `tartans` |
| Windows 10 | `Administrator` | `tartans` |
