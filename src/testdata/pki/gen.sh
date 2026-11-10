#!/bin/sh
# Generates the test PKI in src/testdata/pki. Everything is valid for 100
# years from generation; tests pick the verification time themselves.
set -e
days=36500
ext() { # $1 = SAN, $2 = EKU
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' "$2" "$1"
}
san="DNS:localhost,DNS:*.example.test,IP:127.0.0.1,IP:::1"

# Root CA (P-256).
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days $days -subj "/CN=ztls test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem

# Intermediate CA (P-256), signed by the root.
openssl ecparam -name prime256v1 -genkey -noout -out intermediate.key
openssl req -new -key intermediate.key -sha256 -subj "/CN=ztls test intermediate" -out intermediate.csr
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > intermediate.ext
openssl x509 -req -in intermediate.csr -CA ca.pem -CAkey ca.key -set_serial 2 -days $days -sha256 -extfile intermediate.ext -out intermediate.pem

# Server leaves: P-256, RSA 2048, Ed25519, all signed by the root.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out server-ec.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out server-rsa.key 2>/dev/null
openssl genpkey -algorithm Ed25519 -out server-ed25519.key
ext "$san" serverAuth > server.ext
for k in ec rsa ed25519; do
  openssl req -new -key server-$k.key -subj "/CN=localhost" -out server-$k.csr
  openssl x509 -req -in server-$k.csr -CA ca.pem -CAkey ca.key -set_serial 1$RANDOM -days $days -extfile server.ext -out server-$k.pem
done

# A P-384 leaf signed by the intermediate, with the intermediate appended
# as the chain a server would send.
openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out server-chain.key
openssl req -new -key server-chain.key -subj "/CN=localhost" -out server-chain.csr
openssl x509 -req -in server-chain.csr -CA intermediate.pem -CAkey intermediate.key -set_serial 3 -days $days -extfile server.ext -out server-chain-leaf.pem
cat server-chain-leaf.pem intermediate.pem > server-chain.pem

# A client certificate.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out client.key
openssl req -new -key client.key -subj "/CN=ztls test client" -out client.csr
ext "email:client@example.test" clientAuth > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -set_serial 4 -days $days -extfile client.ext -out client.pem

# A self-signed certificate nobody trusts.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out selfsigned.key
openssl req -x509 -new -key selfsigned.key -days $days -subj "/CN=localhost" -addext "subjectAltName=$san" -out selfsigned.pem

# SHA-1 signatures: on a leaf, which is refused, and on a root, the same
# CA as above, whose own signature nobody checks.
openssl req -new -key server-ec.key -subj "/CN=localhost" -out server-sha1.csr
openssl x509 -req -in server-sha1.csr -CA ca.pem -CAkey ca.key -set_serial 5 -days $days -sha1 -extfile server.ext -out server-sha1.pem
openssl req -x509 -new -key ca.key -sha1 -days $days -subj "/CN=ztls test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca-sha1.pem

# An RSA CA, and leaves it signed with RSASSA-PSS: over SHA-1, which the
# parameters leave unnamed as the default, and over SHA-256.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca-rsa.key 2>/dev/null
openssl req -x509 -new -key ca-rsa.key -sha256 -days $days -subj "/CN=ztls test RSA CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca-rsa.pem
openssl req -new -key server-ec.key -subj "/CN=localhost" -out server-pss.csr
for h in sha1 sha256; do
  openssl x509 -req -in server-pss.csr -CA ca-rsa.pem -CAkey ca-rsa.key -set_serial 6 -days $days -$h \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -extfile server.ext -out server-pss-$h.pem
done

rm -f *.csr *.ext server-chain-leaf.pem
