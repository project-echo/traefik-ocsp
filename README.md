
## About

This is a [Traefik plugin](https://plugins.traefik.io/create) to turn [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1) OCSP over HTTP GET style requests to POST style.

Main reason for this plugin to exist is to handle cases where GET request URL contains double `//` characters, which Vault PKI engine [OCSP requests handler](https://developer.hashicorp.com/vault/api-docs/secret/pki#ocsp-request) has trouble parsing.

The plugin matches a request by its path prefix (i.e. `/ocsp`), extracts the remainder of data from URL path, converts it into binary body contents and rewrites the request from GET to POST with proper headers.

## Usage

For a plugin to be active for a given Traefik instance, it must be declared in the static configuration.

Plugins are parsed and loaded exclusively during startup, which allows Traefik to check the integrity of the code and catch errors early on.
If an error occurs during loading, the plugin is disabled.

For security reasons, it is not possible to start a new plugin or modify an existing one while Traefik is running.

Once loaded, middleware plugins behave exactly like statically compiled middlewares.
Their instantiation and behavior are driven by the dynamic configuration.

Plugin dependencies must be [vendored](https://golang.org/ref/mod#vendoring) for each plugin.
Vendored packages should be included in the plugin's GitHub repository. ([Go modules](https://blog.golang.org/using-go-modules) are not supported.)

### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

```yaml
# Static configuration

experimental:
  plugins:
    ocsp:
      moduleName: github.com/project-echo/traefik-ocsp
      version: v0.1.4
```

Here is an example of a file provider dynamic configuration (given here in YAML), where the interesting part is the `http.middlewares` section:

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - ocsp

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    ocsp:
      plugin:
        PathPrefixes: ["/ocsp"]
        PathRegexp: "^/v1/[^/]+/ocsp"
```

The `PathPrefix` regexp should always match from the beginning of path. Invalid regexp pattern will panic the middleware plugin on initialization.

### Local Mode

Traefik also offers a developer mode that can be used for temporary testing of plugins not hosted on GitHub.
To use a plugin in local mode, the Traefik static configuration must define the module name (as is usual for Go packages) and a path to a [Go workspace](https://golang.org/doc/gopath_code.html#Workspaces), which can be the local GOPATH or any directory.

The plugins must be placed in `./plugins-local` directory,
which should be in the working directory of the process running the Traefik binary.
The source code of the plugin should be organized as follows:

```
./plugins-local/
    └── src
        └── github.com
            └── project-echo
                └── traefik-ocsp
                    ├── ocsp.go
                    ├── ocsp_test.go
                    ├── go.mod
                    ├── LICENSE
                    ├── Makefile
                    └── README.md
```

```yaml
# Static configuration

experimental:
  localPlugins:
    ocsp:
      moduleName: github.com/project-echo/traefik-ocsp
```

(In the above example, the `ocsp` plugin will be loaded from the path `./plugins-local/src/github.com/project-echo/traefik-ocsp`.)

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - ocsp

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    ocsp:
      plugin:
        PathPrefixes: ["/ocsp"]
        PathRegexp: "^/v1/[^/]+/ocsp"
```
