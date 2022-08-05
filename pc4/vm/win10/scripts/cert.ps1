#!Powershell

###############################
###### Trust Certificate ######
###############################

$file = (Get-ChildItem -Path "C:\challenge-root-ca.pem")

$file | Import-Certificate -CertStoreLocation cert:\LocalMachine\Root