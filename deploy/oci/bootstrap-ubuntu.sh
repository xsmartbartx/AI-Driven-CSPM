#!/usr/bin/env bash
# One-time setup of a fresh Ubuntu VM (OCI Ubuntu 22.04/24.04, x86 or ARM): Docker, and the VM's own firewall for 80/443.
# READ IT FIRST, then run as a user with sudo:   bash bootstrap-ubuntu.sh
# It does NOT open the OCI network (do that in the console: see replica/oci-deploy.md) and does not touch SSH (port 22 stays as is).
set -euo pipefail
if ! command -v docker >/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg git
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker "$USER"
  echo "Docker installed. Log out and back in so the docker group applies."
fi
# OCI's Ubuntu images ship iptables rules that reject everything except SSH. Allow web traffic before the final REJECT rule.
for p in 80 443; do
  sudo iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT 5 -p tcp --dport "$p" -m state --state NEW -j ACCEPT
done
sudo apt-get install -y iptables-persistent >/dev/null 2>&1 || true
sudo netfilter-persistent save >/dev/null 2>&1 || sudo sh -c 'iptables-save > /etc/iptables/rules.v4'
echo "Firewall: 80 and 443 allowed on the VM."
echo "Next: copy .env.example to .env, fill it in, then:  docker compose up -d --build"
