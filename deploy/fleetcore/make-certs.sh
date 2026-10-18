#!/bin/sh
# Makes the certificates for compose.secure.yaml with openssl: a CA for the MongoDB cluster, the MongoDB server's certificate, and a client certificate for the administrator and one tenant
# server. Replace this with your own PKI in production; the point is the shape. Client certificate subjects must differ from the server's in O/OU/DC (MongoDB would take them for
# cluster members otherwise).
set -eu
out="${1:-certs}"
mkdir -p "$out" && cd "$out"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 825 -subj "/O=cluster/CN=cluster CA" -out ca.pem
issue() { # name subject usage san
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"
  printf "extendedKeyUsage=%s\n%s\n" "$3" "${4:-}" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  cat "$1.crt" "$1.key" > "$1.pem"
  rm -f "$1.csr" "$1.ext" "$1.crt"
}
issue mongo "/O=cluster/CN=mongo" "serverAuth,clientAuth" "subjectAltName=DNS:mongo,DNS:localhost,IP:127.0.0.1"
issue admin "/O=operators/CN=admin" "clientAuth"
issue tenant-acme "/O=tenants/CN=acme-mdm-1" "clientAuth"
openssl rand -base64 756 > keyfile && chmod 400 keyfile
chmod 600 *.pem *.key
echo "wrote $PWD: ca.pem, mongo.pem, admin.pem, tenant-acme.pem, keyfile"
