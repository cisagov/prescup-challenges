#!Powershell

################################################
###### Change Hostname via Scheduled Task ######
################################################

$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\change_hostname.ps1'
$taskTrigger = New-ScheduledTaskTrigger -AtLogon
$taskName = "Change Hostname"
$taskDescription = "Changes hostname to name of vm in topo"

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Description $taskDescription


#################################################
###### Change Wallpaper via Scheduled Task ######
#################################################

$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\wallpaper.ps1'
$taskTrigger = New-ScheduledTaskTrigger -AtLogon
$taskName = "Change Wallpaper"
$taskDescription = "Changes Wallpaper"

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Description $taskDescription