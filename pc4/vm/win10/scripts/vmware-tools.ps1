#!Powershell

##################################
###### VMWare Tools Install ######
##################################

$ProgressPreference = "SilentlyContinue"

$webclient = New-Object System.Net.WebClient
$version_url = "https://packages.vmware.com/tools/releases/latest/windows/x64/"
$raw_package = $webclient.DownloadString($version_url)
$raw_package -match "VMware-tools[\w-\d\.]*\.exe"
$package = $Matches.0

$url = "https://packages.vmware.com/tools/releases/latest/windows/x64/$package"
$exe = "$Env:TEMP\$package"

Write-Output "***** Downloading VMware Tools"
$webclient.DownloadFile($url, $exe)

$parameters = '/S /v "/qn REBOOT=R ADDLOCAL=ALL"'

Write-Output "***** Installing VMware Tools"
Start-Process $exe $parameters -Wait

Write-Output "***** Deleting $exe"
Remove-Item $exe