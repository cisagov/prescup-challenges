<img src="../../../../../logo.png" height="250px">

# Winston Wolf

## Solution

The application currently checks the following for evidence of virtualization;
the successful player will need to perform the following steps in order to get
the application to reveal the flag:

1. Registry: Change the names/descriptions, or remove items entirely
2. Filesystem: Delete files completely
3. Windows Services: modify name and description of service
    a. To change the service display name, run
       `sc config <old_service_name> displayname=<new_service_name>`
    b. Stop the service
    c. Open `regedit.exe` (Registry Editor)
    d. Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services` and
       find the subkey with your service's name
    e. Right-click the subkey you found, and select `Rename`, then enter a new
       name for the service
    f. Restart the computer to force the service control manager
       (`Services.exe`) to accept the changes.
4. Network Interfaces: Ensure name/description doesn't indicate virtualization
    - The simplest way around this is to completely remove the network interface
      from the guest before running the program.

## Registry Key examples:
    - `SYSTEM\ControlSet001\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S\5&1ec51bf7&0&000000\FriendlyName`
    - `SYSTEM\ControlSet001\Enum\PCI\VEN_15AD&DEV_0405&SUBSYS_040515AD&REV_00\3&61aaa01&0&78\DeviceDesription`

## Filesystem Item examples:
    - `vmwaretools` (rename or remove tray icon)
    - `C:\Program Files\VMWare`
    - `C:\windows\System32\Drivers\Vmmouse.sys`
    - `C:\windows\System32\Drivers\VMToolsHook.dll`
    - etc.

## Windows Service examples:
    - VMTools
    - Vmhgfs
    - VMMEMCTL
    - Vmmouse
    - Vmrawdsk
    - Vmusbmouse
    - Vmvss
    - Vmscsi
    - Vmxnet
    - vmx_svga
    - Vmware Tools
    - Vmware Physical Disk Helper Service

<br><br>

Flag - `47°27'0"N 122°18'31"W`

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../../LICENSE.md) file for details.