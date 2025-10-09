#!/usr/bin/env bash
set -euo pipefail

mkdir -p pki
cd pki

# Root CA
openssl req -x509 -newkey rsa:4096 -days 3650 -sha256 -nodes \
  -subj "/CN=DMJ One Root CA/O=dmj.one/C=IN" \
  -keyout dmj-root.key -out dmj-root.crt

# Leaf signer
openssl req -newkey rsa:3072 -nodes \
  -subj "/CN=dmj.one Document Signer/O=dmj.one/C=IN" \
  -keyout dmj-signer.key -out dmj-signer.csr

cat > ext.cnf <<EOF
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation
extendedKeyUsage = codeSigning, emailProtection
subjectAltName = DNS:dmj.one
EOF

openssl x509 -req -in dmj-signer.csr -CA dmj-root.crt -CAkey dmj-root.key -CAcreateserial \
  -out dmj-signer.crt -days 1825 -sha256 -extfile ext.cnf

# PKCS#12 bundle for the signer service
openssl pkcs12 -export -inkey dmj-signer.key -in dmj-signer.crt -certfile dmj-root.crt \
  -out dmj-signer.p12 -name dmj-signer

echo "P12 at ./dmj-signer.p12 (set P12_PASSWORD accordingly)."
