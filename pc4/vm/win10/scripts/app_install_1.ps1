#!Powershell

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

################################
###### Chocolatey Install ######
################################

Write-Output "***** Chocolatey Install"

Invoke-Webrequest -Uri https://chocolatey.org/install.ps1 -OutFile chocolatey-install.ps1

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))


#########################################
###### Chocolatey Packages Install ######
#########################################

Write-Output "***** Chocolatey Package Install"

$chocolatey_packages = Get-Content -Path C:\chocolatey_packages.txt
foreach ($choco_package in $chocolatey_packages){
    Invoke-Expression "choco install $choco_package -y --no-progress --acceptlicense"
}
