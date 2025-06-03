
# Testing the OCSP middleware

This `test/` folder contains an integration test setup that automates Traefik plugin testing with Docker Compose and tests requests with `curl` calls.

Run `./integration-test.sh` to start services, and check different request/response values.

See `docker-compose.yaml` for details on the Traefik middleware setup. It loads the `ocsp` plugin as a local plugin instance by mapping the latest code in this repo in via a volume mount.

See `fixture.go` and `Dockerfile` for local fake OCSP responder. It responds based on incoming cert serial numbers, not an actual revocation list.

These tests depend on a set of self-signed testing certs/keys, if needed they can be re-generated using `step` CLI and `./pki-init.sh` script. If you re-generate the certs, use the newly generated `issuerPem` value in middleware annotation label for tests to keep on working.

### Resources

* [RFC6066](https://www.ietf.org/rfc/rfc6066.txt) -- Transport Layer Security (TLS) Extensions: Extension Definitions
* [RFC2560](https://www.ietf.org/rfc/rfc2560.txt) -- X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP
* [OCSP Validation with OpenSSL](https://akshayranganath.github.io/OCSP-Validation-With-Openssl/)
* [OCSP Stapling in Firefox](https://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/)
