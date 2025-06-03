#!/usr/bin/env bash

set -euo pipefail
# set -x

output=$(mktemp)

cleanup() {
  rm "${output}"
  docker compose down
}

trap "cleanup" EXIT

check() {
  read output
  if [[ "$output" != "true" ]]; then
    echo "check '${1}' is not true"
    exit 1
  fi
}

docker compose up --detach --wait

sleep 2

echo "Doing OCSP GET request..."

data="MFUwUzBRME8wTTAJBgUrDgMCGgUABBT3O18PnpuclNZtpOrVxflCqr5EhAQUpAUtGSmhUlvQrdQvR22AQcL1TkICFATjZCxaxNrh6M4oUoMxQ6O0hW24"
baseurl="http://httpbin.docker.localhost/anything/ocsp"
curl --silent --output "${output}" "${baseurl}/${data}"

echo "Testing OCSP GET result values..."

jq ".method == \"POST\"" "${output}" | check "method is POST"
jq ".url == \"${baseurl}\"" "${output}" | check "url is ${baseurl}"
jq ".headers[\"Content-Type\"][0] == \"application/ocsp-request\"" "${output}" | check "content-type is application/ocsp-request"
jq ".data == \"data:application/ocsp-request;base64,${data}\"" "${output}" | check "body data contains byte stream"

echo "Doing 'good' cert request..."
curl --insecure --silent --output "${output}" \
  --cert ./pki/ocsptest_good.crt \
  --key ./pki/ocsptest_good.key \
  https://ocsptest.docker.localhost/get
echo "Testing 'good' cert result values..."
jq ".headers[\"X-Forwarded-Tls-Client-Cert-Info\"][0] | contains(\"ocsptest_good\")" "${output}" | check "ocsptest_good cert info not found in response"

echo "Doing 'unknown' cert request..."
curl --insecure --silent --output "${output}" \
  --cert ./pki/ocsptest_unknown.crt \
  --key ./pki/ocsptest_unknown.key \
  https://ocsptest.docker.localhost/get
echo "Testing 'unknown' cert result values..."
jq ".headers[\"X-Forwarded-Tls-Client-Cert-Info\"][0] | contains(\"ocsptest_unknown\")" "${output}" | check "ocsptest_unknown cert info not found in response"

echo "Doing 'invalid' cert request..."
curl --insecure --silent --output "${output}" \
  --cert ./pki/ocsptest_invalid.crt \
  --key ./pki/ocsptest_invalid.key \
  https://ocsptest.docker.localhost/get
echo "Testing 'invalid' cert result values..."
if ! grep -q "Client verification failed (ocsp response fail)" "${output}"; then
  check "ocsptest_invalid cert request did not fail, but should have"
fi

echo "Doing 'revoked' cert request..."
curl --insecure --silent --output "${output}" \
  --cert ./pki/ocsptest_revoked.crt \
  --key ./pki/ocsptest_revoked.key \
  https://ocsptest.docker.localhost/get
echo "Testing 'revoked' cert result values..."
if ! grep -q "Client certificate has been revoked" "${output}"; then
  check "ocsptest_revoked cert request did not fail, but should have"
fi

echo "All good!"

docker compose down
