#!/bin/bash

# Copyright 2025 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


set -euo pipefail

echo "Copying k3s binary..."
sudo cp k3s /usr/local/bin/

echo "Creating audit log directory..."
sudo mkdir -p -m 700 /var/lib/rancher/k3s/server/logs

echo "Creating Kubernetes audit policy file..."
sudo tee /var/lib/rancher/k3s/server/audit.yaml > /dev/null <<EOF
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
EOF

echo "Copying PSA file..."
sudo cp psa.yaml /var/lib/rancher/k3s/server/

echo "Creating K3s registry configuration directory..."
sudo mkdir -p /etc/rancher/k3s

echo "Writing container registry configuration..."
sudo cp registries.yaml /etc/rancher/k3s/

echo "Creating directory for registry CA certificate..."
sudo mkdir -p /etc/rancher/k3s/registry-certs/registry.skills.hub/

echo "Copying CA certificate into place..."
sudo cp certs/ca.crt /etc/rancher/k3s/registry-certs/registry.skills.hub/ca.crt

echo " All setup steps completed successfully!"


