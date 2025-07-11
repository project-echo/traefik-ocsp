
## About

This is a [Traefik plugin](https://plugins.traefik.io/create) to integrate TLS certificate OCSP requests as a Middleware.

There are two modes of operation, `rewrite` mode is to turn [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1) OCSP over HTTP GET style requests to POST style. Main reason for this plugin mode to exist is to handle cases where GET request URL contains double `//` characters, which Vault PKI engine [OCSP requests handler](https://developer.hashicorp.com/vault/api-docs/secret/pki#ocsp-request) has trouble parsing. The plugin matches a request by its path prefix (i.e. `/ocsp`), extracts the remainder of data from URL path, converts it into binary body contents and rewrites the request from GET to POST with proper headers.

The other `check` mode is to actively generate an OCSP cert validation request, and parsing the response from configured OCSP endpoint, deciding if it is still a good cert. This helps make sure any revoked certificates can not continue with their request to Traefik.

## Usage

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration defines a plugin:

```yaml
# Static configuration

experimental:
  plugins:
    ocsp:
      moduleName: github.com/project-echo/traefik-ocsp
      version: v0.2.0
```

Here is an example of a file provider dynamic configuration, where the interesting part is the `http.middlewares` section:

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo-ocsp-endpoint.localhost`)
      service: demo-ocsp-endpoint
      entryPoints:
        - web
      middlewares:
        - ocsp

  services:
   demo-ocsp-endpoint:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    ocsp:
      plugin:
        mode: "rewrite"
        rewrite:
          pathPrefixes: ["/ocsp"]
          pathRegexp: "^/v1/[^/]+/ocsp"
```

The `pathPrefix` regexp should always match from the beginning of path. Invalid regexp pattern will panic the middleware plugin on initialization.

For the `check` mode config set the issuers config:

```yaml
http:
  #...

  middlewares:
    ocsp:
      plugin:
        mode: "check"
        issuers:
          - ocspEndpoint: http://demo-ocsp-endpoint.localhost/ocsp
            issuerPem: |
              -----BEGIN CERTIFICATE-----
              ...
              -----END CERTIFICATE-----
```

The client certificate is parsed to find its authority key id, which is then looked up in the configured `issuers` list `issuerPem` certs, when found that `ocspEndpoint` is used for the OCSP request.

The plugin can be configured to log at debug level, and also log full OCSP requests if needed by setting `logLevel: "debug"` and `logRequests: true`:

```yaml
http:
  #...

  middlewares:
    ocsp:
      plugin:
        mode: "check"
        logLevel: "debug"
        logRequests: true
        issuers:
          # - ...
```

## Kubernetes middleware example

Here's how to use this plugin as Traefik middleware as Kubernetes CRD:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ocsp-check
  namespace: testing
spec:
  plugin:
    ocsp:
      issuers:
      # required client certs CA public key and internal ocsp endpoint to check
      - issuerPem: |
          -----BEGIN CERTIFICATE-----
          MIIE5zCCAs+gAwIBAgIRAN0cOiyXvuhiU2+j7PD1UuYwDQYJKoZIhvcNAQELBQAw
          ...
          gcCdVdM02YvXSfQ=
          -----END CERTIFICATE-----
        ocspEndpoint: http://vault-internal.vault.svc.cluster.local:8200/v1/pki_test/ocsp
      logLevel: debug
      logRequests: false
      mode: check
```

And then add it as an annotation to ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: https
    # require client certs
    traefik.ingress.kubernetes.io/router.tls.options: testing-test-ca-client-auth@kubernetescrd
    # validate certs with ocsp requests
    traefik.ingress.kubernetes.io/router.middlewares: testing-ocsp-check@kubernetescrd
  ...
```
