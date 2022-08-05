#!Powershell

#####################
###### Cleanup ######
#####################

Function Cleanup {

    Clear-Host

    ## Stops the windows update service.
    Get-Service -Name wuauserv | Stop-Service -Force -Verbose -ErrorAction SilentlyContinue

    ## Deletes the contents of windows software distribution.
    Get-ChildItem "C:\Windows\SoftwareDistribution\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue | Remove-Item -Force -Verbose -recurse -ErrorAction SilentlyContinue

    ## Deletes the contents of the Windows Temp folder.
    Get-ChildItem "C:\Windows\Temp\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue | Remove-Item -Force -Verbose -recurse -ErrorAction SilentlyContinue

    ## Delets all files and folders in user's Temp folder.
    Get-ChildItem "C:\users\*\AppData\Local\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Verbose -recurse -ErrorAction SilentlyContinue

    ## Remove all files and folders in user's Temporary Internet Files.
    Get-ChildItem "C:\users\*\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -Recurse -Force -Verbose -ErrorAction SilentlyContinue | Remove-Item -Force -recurse -ErrorAction SilentlyContinue

    ## Remove Scripts from C:\
    Remove-Item C:\Chocolatey-install.ps1 -ErrorAction SilentlyContinue
    Remove-Item C:\chocolatey_packages.txt -ErrorAction SilentlyContinue
    Remove-Item C:\pip_packages.txt -ErrorAction SilentlyContinue
    Remove-Item C:\vscode_extensions.txt -ErrorAction SilentlyContinue

}

Cleanup