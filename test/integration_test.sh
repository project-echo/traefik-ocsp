#!/usr/bin/env bash

set -euo pipefail

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

echo "Testing result values..."

jq ".method == \"POST\"" "${output}" | check "method is POST"
jq ".url == \"${baseurl}\"" "${output}" | check "url is ${baseurl}"
jq ".headers[\"Content-Type\"] == \"application/ocsp-request\"" "${output}" | check "content-type is application/ocsp-request"
jq ".data == \"data:application/octet-stream;base64,${data}\"" "${output}" | check "body data contains byte stream"

echo "All good!"

docker compose down
