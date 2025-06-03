#!/usr/bin/env bash

set -euo pipefail
set -x

if [ -d "./pki" ]; then
    echo "Directory ./pki already exists. Please remove it before running this script."
    exit 1
fi

mkdir -p ./pki
cd ./pki

# Based on this guide:
#   https://smallstep.com/docs/step-cli/basic-crypto-operations/#requirements

# Root and intermediate CAs
step certificate create \
  "ocsptest root ca" \
  root_ca.crt \
  root_ca.key \
  --insecure \
  --no-password \
  --kty=RSA \
  --profile root-ca

step certificate create \
  "ocsp web intermediate ca" \
  intermediate_ca.crt \
  intermediate_ca.key \
  --insecure \
  --no-password \
  --profile intermediate-ca \
  --kty=RSA \
  --ca root_ca.crt \
  --ca-key root_ca.key

step certificate create \
  "ocsp client auth ca" \
  clientauth_ca.crt \
  clientauth_ca.key \
  --insecure \
  --no-password \
  --profile intermediate-ca \
  --kty=RSA \
  --ca root_ca.crt \
  --ca-key root_ca.key

# Test website certs
certs=(
  "ocsptest.docker.localhost"
)
for cert in "${certs[@]}"; do
  step certificate create \
    "${cert}" "${cert}.crt" "${cert}.key" \
    --insecure \
    --no-password \
    --profile leaf \
    --not-after=26304h \
    --kty=RSA \
    --ca ./intermediate_ca.crt \
    --ca-key ./intermediate_ca.key \
    --bundle
done

# Test client certs
certs=(
  "ocsptest_good"
  "ocsptest_revoked"
  "ocsptest_invalid"
  "ocsptest_unknown"
)
for cert in "${certs[@]}"; do
  step certificate create \
    "${cert}" "${cert}.crt" "${cert}.key" \
    --insecure \
    --no-password \
    --profile leaf \
    --kty=RSA \
    --not-after=26304h \
    --ca ./clientauth_ca.crt \
    --ca-key ./clientauth_ca.key
done

echo "Certificates created successfully."

echo "Value to use as issuerPem in the config:"
echo ""
awk 'NR>1 { last=$0 } NR>2 { print prev } { prev=last }' pki/clientauth_ca.crt | tr -d '\n'
echo ""
