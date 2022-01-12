#!/bin/bash

# Copyright 2022 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


checka1=$(grep 'readOnlyRootFilesystem: true' ./challenge/psp.yaml) #readOnlyRootFileSystem
checka2=$(grep 'privileged: false' ./challenge/psp.yaml) #privileged set to false
checka3=$(grep 'allowPrivilegeEscalation: false' ./challenge/psp.yaml) #allowPrivilegeEscalation false"

checkb1=$(grep 'runAsUser: true' ./challenge/psp.yaml) #Have container run as user
checkb2=$(grep 'MustRunAsNonRoot: true' ./challenge/psp.yaml) #Must run as non-root
checkb3=$(grep 'hostIPC: false' ./challenge/psp.yaml) #hostIPC false
checkb4=$(grep 'hostPID: false' ./challenge/psp.yaml) #hostPID false

checkc=$(grep 'apiVersion: audit.k8s.io' ./challenge/psp.yaml) #Enable audit logging

checkd=$(grep 'kind: EncryptionConfiguration' ./challenge/psp.yaml) #Encryption configuration

checke=$(grep 'kind: LimitRange' ./challenge/psp.yaml) #Limit range

checkf1=$(grep 'name: deny-all-ingress' ./challenge/psp.yaml) #deny all ingress
checkf2=$(grep 'name: deny-all-egress' ./challenge/psp.yaml) #deny all egress
checkf3=$(grep 'name: default-deny-all' ./challenge/psp.yaml) #deny all ingress and egress


if [ ${#checka1} -ne 0 ] && [ ${#checka2} -ne 0 ] && [ ${#checka3} -ne 0 ]; then
    echo "checka: Success - File system is set to read only. Privileged containers are prevented. Allow privilege escalation is set to false."
else 
    echo "checka: Failure - File system is NOT set to read only and/or Privileged containers are NOT prevented and/or Allow privilege esclation is NOT set to false."
fi

if [ ${#checkb1} -ne 0 ] && [ ${#checkb2} -ne 0 ] && [ ${#checkb3} -ne 0 ] && [ ${#checkb4} -ne 0 ]; then
    echo "checkb: Success - Must run as user is set as true. MustRunAsNonRoot is set as true. hostIPC and hostPID set as false."
else 
    echo "checkb: Failure - Must run as user is NOT set as true and/or MustRunAsNonRoot is NOT set to true and/or hostPID and hostIPC are NOT set to false."
fi

if [ ${#checkc} -ne 0 ]; then
    echo "checkc: Success - Audit logging is enabled."
else 
    echo "checkc: Failure - Audit logging is NOT enabled."
fi

if [ ${#checkd} -ne 0 ]; then
    echo "checkd: Success - Encryption is configured correctly."
else 
    echo "checkd: Failure - Encryption is NOT configured correctly."
fi

if [ ${#checke} -ne 0 ]; then
    echo "checke: Success - Limit range on containers is configured correctly."
else 
    echo "checke: Failure - Limit range on containers is NOT configured correctly."
fi
if [ ${#checkf3} -ne 0 ] || ([ ${#checkf1} -ne 0 ] && [ ${#checkf2} -ne 0 ]); then
    echo "checkf: Success - default-deny-all or deny-all-ingress and deny-all-egress are set correctly."
else 
    echo "checkf: Failure - deny-all-ingress and/or deny-all-egress are not set correctly."
fi
