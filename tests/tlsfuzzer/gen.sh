#!/bin/sh
# Generates the client certificates tlsfuzzer presents to port 4434, signed
# by the test CA in src/testdata/pki and valid for 100 years. The P-256 one
# there serves the ECDSA scripts; these are for the RSA and EdDSA ones.
set -e
cd "$(dirname "$0")"
ca=../../src/testdata/pki
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > client.ext
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out client-rsa.key 2>/dev/null
openssl genpkey -algorithm Ed25519 -out client-ed25519.key
serial=10
for k in rsa ed25519; do
  openssl req -new -key client-$k.key -subj "/CN=ztls tlsfuzzer client" -out client-$k.csr
  openssl x509 -req -in client-$k.csr -CA $ca/ca.pem -CAkey $ca/ca.key -set_serial $serial -days 36500 -extfile client.ext -out client-$k.pem
  serial=$((serial + 1))
done
rm -f ./*.csr client.ext
