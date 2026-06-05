#!/usr/bin/env bash
# scripts/gen-dev-certs.sh, generate a tiny mTLS PKI for local dev.
#
#   ca.crt + ca.key       → trust anchor
#   server.crt + server.key → control plane (cn=hopframe-cp)
#   sensor.crt + sensor.key → sensor (cn=hopframe-sensor)
#
# Usage:
#   ./scripts/gen-dev-certs.sh [out_dir]
#
# Out dir defaults to /tmp/hopframe-certs.

set -euo pipefail
OUT="${1:-/tmp/hopframe-certs}"
mkdir -p "$OUT"
cd "$OUT"

if ! command -v openssl > /dev/null; then
  echo "openssl not found"; exit 1
fi

cat > ca.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = hopframe-dev-ca
EOF

cat > server.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = hopframe-cp
[v3_req]
subjectAltName = @alt
[alt]
DNS.1 = localhost
DNS.2 = control-plane
IP.1  = 127.0.0.1
EOF

cat > sensor.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = hopframe-sensor
EOF

echo "==> CA"
openssl genrsa -out ca.key 2048 >/dev/null 2>&1
openssl req -x509 -new -key ca.key -days 365 -config ca.cnf -out ca.crt 2>/dev/null

echo "==> server (control plane)"
openssl genrsa -out server.key 2048 >/dev/null 2>&1
openssl req -new -key server.key -config server.cnf -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
  -extensions v3_req -extfile server.cnf -out server.crt 2>/dev/null

echo "==> sensor (client)"
openssl genrsa -out sensor.key 2048 >/dev/null 2>&1
openssl req -new -key sensor.key -config sensor.cnf -out sensor.csr 2>/dev/null
openssl x509 -req -in sensor.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 \
  -out sensor.crt 2>/dev/null

rm -f *.csr *.cnf *.srl
chmod 600 *.key
echo
echo "  files in $OUT:"
ls -1 "$OUT"
