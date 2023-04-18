#!Powershell

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

####################################
###### Python Package Install ######
####################################

Write-Output "***** Python Files"

pip install -r C:\pip_packages.txt

######################################
###### VSCode Extension Install ######
######################################

Write-Output "***** VSCode Extensions"

$codeXts = Get-Content -Path C:\vscode_extensions.txt
foreach ($codeXt in $codeXts){
    Invoke-Expression "code --install-extension $codeXt --reuse-window"
}

#################################
###### Manual App Installs ######
#################################

Write-Output "***** Manual Apps"

# Network Miner
Invoke-WebRequest -Uri https://www.netresec.com/?download=NetworkMiner -OutFile C:\Users\Administrator\Desktop\NetworkMiner.zip
Expand-Archive C:\Users\Administrator\Desktop\NetworkMiner.zip -DestinationPath "C:\Users\Administrator\Desktop\Network Miner\"
rm C:\Users\Administrator\Desktop\NetworkMiner.zip

# RegRipper
Invoke-WebRequest -Uri https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip -OutFile "C:\Users\Administrator\Desktop\RegRipper3.0-master.zip"
Expand-Archive C:\Users\Administrator\Desktop\RegRipper3.0-master.zip -DestinationPath "C:\Users\Administrator\Desktop\"
rm C:\Users\Administrator\Desktop\RegRipper3.0-master.zip

# Registry Viewer
Invoke-WebRequest -Uri https://ad-exe.s3.amazonaws.com/AccessData_Registry_Viewer_2.0.0.exe -OutFile "C:\Users\Administrator\Desktop\RegistryViewer.exe"
Start-Process -Wait -FilePath "C:\Users\Administrator\Desktop\RegistryViewer.exe" -Argument "/S /v/qn" -PassThru
rm C:\Users\Administrator\Desktop\RegistryViewer.exe

# Cyber Chef
# Note: If new version released, may need to update link url
Invoke-WebRequest -Uri https://gchq.github.io/CyberChef/CyberChef_v9.46.0.zip -OutFile "C:\Users\Administrator\Desktop\CyberChef_v9.46.0.zip"
Expand-Archive C:\Users\Administrator\Desktop\CyberChef_v9.46.0.zip -DestinationPath "C:\Users\Administrator\Desktop\cyberchef\"
rm C:\Users\Administrator\Desktop\CyberChef_v9.46.0.zip

# Nmap
Invoke-WebRequest -Uri "https://nmap.org/dist/nmap-7.60-setup.exe" -OutFile "C:\Users\Administrator\Desktop\nmap.exe"
Start-Process -Wait -FilePath "C:\Users\Administrator\Desktop\nmap.exe" -Argument "/S" -PassThru
rm C:\Users\Administrator\Desktop\nmap.exe

# Procdot Dependency - windump
Invoke-Expression "choco install winpcap -y --acceptlicense --force"
Invoke-WebRequest -Uri "http://www.winpcap.org/windump/install/bin/windump_3_9_5/WinDump.exe" -OutFile "C:\Users\Administrator\Desktop\windump.exe"

# Procdot
# Note: You must manually configure Procdot with the windump and graphviz exe paths. Windump will be on the desktop.
# The path to dot graphviz is C:\Program Files\Graphviz\bin\dot.exe
Install-Module -Name 7Zip4Powershell -force
Invoke-WebRequest -Uri "https://www.procdot.com/download/procdot/binaries/procdot_1_22_57_windows.zip" -OutFile "C:\Users\Administrator\Desktop\procdot.zip"
Expand-7Zip -ArchiveFileName C:\Users\Administrator\Desktop\procdot.zip -Password "procdot" -TargetPath C:\Users\Administrator\Desktop\procdot
rm C:\Users\Administrator\Desktop\procdot.zip

# Plist editor
Invoke-WebRequest -Uri "http://www.icopybot.com/plisteditor_setup.exe" -OutFile "C:\Users\Administrator\Desktop\plisteditor_setup.exe"
Start-Process -Wait -FilePath "C:\Users\Administrator\Desktop\plisteditor_setup.exe" -Argument "/S" -PassThru
rm C:\Users\Administrator\Desktop\plisteditor_setup.exe

# VeraCrypt
Invoke-WebRequest -Uri "https://launchpad.net/veracrypt/trunk/1.25.9/+download/VeraCrypt_Setup_x64_1.25.9.msi" -OutFile "C:\Users\Administrator\Desktop\veracrypt.msi"
Start-Process -Wait -FilePath "C:\Users\Administrator\Desktop\veracrypt.msi" -Argument "/quiet ACCEPTLICENSE=YES" -PassThru
rm C:\Users\Administrator\Desktop\veracrypt.msi

# x64 dgb shortcut
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\x64dbg.lnk")
$Shortcut.TargetPath = "C:\ProgramData\chocolatey\bin\x64dbg.exe"
$Shortcut.Save()

# FTK Imager
# Start-Process -Wait -FilePath "C:\AccessData_FTK_Imager_(x64)" -Argument "/S /v/qn"

# Move README to desktop
mv C:\tools_README.txt C:\Users\Administrator\Desktop
