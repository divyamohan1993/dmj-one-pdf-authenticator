#!/usr/bin/env bash
s#!/usr/bin/env bash
et -euo pipefail

# Ubuntu 22.04/24.04 assumed
sudo apt-get update
sudo apt-get install -y openjdk-21-jdk maven nginx ufw

# user + dirs
sudo useradd -r -m -d /opt/dmj -s /usr/sbin/nologin dmj || true
sudo mkdir -p /opt/dmj/pdf-signer
sudo chown -R dmj:dmj /opt/dmj
sudo mkdir -p /etc/dmj
sudo touch /etc/nginx/conf.d/dmj_pdfsigner_port.conf

# firewall (optional)
sudo ufw allow OpenSSH || true
sudo ufw allow 80/tcp || true

# nginx site
sudo cp signer-vm/ops/nginx-site.conf /etc/nginx/sites-available/dmj-pdfsigner.conf
sudo ln -sf /etc/nginx/sites-available/dmj-pdfsigner.conf /etc/nginx/sites-enabled/dmj-pdfsigner.conf
sudo nginx -t
sudo systemctl restart nginx

# build app
pushd signer-vm
sudo -u dmj mvn -q -DskipTests package
popd
sudo cp signer-vm/target/pdf-signer-1.0.0.jar /opt/dmj/pdf-signer/

# env + service
sudo cp signer-vm/ops/dmj-pdfsigner.env.sample /etc/default/dmj-pdfsigner
echo "Edit /etc/default/dmj-pdfsigner with your secrets, then:"
echo "  sudo systemctl daemon-reload && sudo systemctl enable --now dmj-pdfsigner"
