#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


# Namespace: cosign-system
kubectl label ns cosign-system \
  kubernetes.io/metadata.name=cosign-system \
  lab=true \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Namespace: 01-nonroot
kubectl create ns 01-nonroot --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns 01-nonroot \
  kubernetes.io/metadata.name=01-nonroot \
  lab=true \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Namespace: 02-immutable
kubectl create ns 02-immutable --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns 02-immutable \
  kubernetes.io/metadata.name=02-immutable \
  lab=true \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Namespace: 03-trusted-images
kubectl create ns 03-trusted-images --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns 03-trusted-images \
  kubernetes.io/metadata.name=03-trusted-images \
  lab=true \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Namespace: 04-psa-enforcement
kubectl create ns 04-psa-enforcement --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns 04-psa-enforcement \
  kubernetes.io/metadata.name=04-psa-enforcement \
  lab=true \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Namespace: 05-sa-token
kubectl create ns 05-sa-token --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns 05-sa-token \
  kubernetes.io/metadata.name=05-sa-token \
  lab=true \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged --overwrite

# Namespace: 06-hardening
kubectl create ns 06-hardening --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns 06-hardening \
  kubernetes.io/metadata.name=06-hardening \
  lab=true --overwrite


