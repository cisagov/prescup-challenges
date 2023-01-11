#!Powershell

# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

###############################
###### Trust Certificate ######
###############################

$file = (Get-ChildItem -Path "C:\challenge-root-ca.pem")

$file | Import-Certificate -CertStoreLocation cert:\LocalMachine\Root
