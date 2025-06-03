# Forked copy notes

This is a forked copy of [ocsp.go](https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.37.0:ocsp/ocsp.go) from https://pkg.go.dev/golang.org/x/crypto library.

Fixes were needed for the `Good` and `Unknown` checks because of bugs (?) in [Yaegi](https://github.com/traefik/yaegi) engine embedded in Traefik.

The `crypto` library license is included in this folder, it is compatible with  Apache 2.0 license used in the rest of this repository.
