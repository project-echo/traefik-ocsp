// Package traefik_ocsp is a plugin to convert OCSP check GET requests to POST,
// or to do the OCSP cert revocation checks.
package traefik_ocsp //nolint:all

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type issuer struct {
	ocspEndpoint string
	issuerCert   *x509.Certificate
}

type middleware struct {
	next         http.Handler
	name         string
	mode         mode
	pathPrefixes []string
	pathRegexp   *regexp.Regexp
	issuers      map[string]issuer
	client       *http.Client
	debug        bool
}

var (
	// ErrInvalidMode when unknown plugin mode is uses.
	ErrInvalidMode = errors.New("unknown plugin mode")
	// ErrInvalidRegexp when regexp patter doesn't compile.
	ErrInvalidRegexp = errors.New("invalid regular expression syntax")
	// ErrInvalidEndpoint when unsupported endpoint URL is used.
	ErrInvalidEndpoint = errors.New("invalid OCSP endpoint URL")
	// ErrInvalidCertificate when provided certificate PEM is invalid.
	ErrInvalidCertificate = errors.New("certificate is invalid")
)

// New creates and returns a new plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Mode == RewriteMode {
		return newRewriteMode(context.Background(), next, config, name)
	}
	if config.Mode == CheckMode {
		return newCheckMode(context.Background(), next, config, name)
	}
	return nil, ErrInvalidMode
}

func newRewriteMode(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var regex *regexp.Regexp
	var err error

	if len(config.Rewrite.PathRegexp) > 0 {
		regex, err = regexp.Compile(config.Rewrite.PathRegexp)
		if err != nil {
			return nil, ErrInvalidRegexp
		}
	}

	m := &middleware{
		name:         name,
		next:         next,
		mode:         RewriteMode,
		pathPrefixes: config.Rewrite.PathPrefixes,
		pathRegexp:   regex,
		debug:        config.Debug,
	}

	return m, nil
}

func newCheckMode(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	issuers := make(map[string]issuer)

	tr := &http.Transport{
		MaxIdleConns:       5,                //nolint:mnd
		IdleConnTimeout:    30 * time.Second, //nolint:mnd
		DisableCompression: true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second, //nolint:mnd
	}

	m := &middleware{
		name:    name,
		next:    next,
		mode:    CheckMode,
		issuers: issuers,
		client:  client,
		debug:   config.Debug,
	}

	for _, cfg := range config.Issuers {
		url, err := url.Parse(cfg.OCSPEndpoint)
		if err != nil {
			return nil, ErrInvalidEndpoint
		}
		if url.Scheme != "http" && url.Scheme != "https" {
			return nil, ErrInvalidEndpoint
		}

		if !strings.HasPrefix(cfg.IssuerPEM, "-----BEGIN CERTIFICATE-----") {
			// Wrap in expected PEM format markers
			cfg.IssuerPEM = fmt.Sprintf(
				"-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
				cfg.IssuerPEM,
			)
		}
		pemBlock, _ := pem.Decode([]byte(cfg.IssuerPEM))
		if pemBlock == nil {
			return nil, ErrInvalidCertificate
		}
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, ErrInvalidCertificate
		}

		// Use the hex version of cert subject key ID for lookup
		keyID := getHexFormatted(cert.SubjectKeyId)
		issuers[keyID] = issuer{
			ocspEndpoint: url.String(),
			issuerCert:   cert,
		}
		m.logInfo(kv(
			"msg", "registered issuer cert",
			"keyid", keyID,
		))
	}
	return m, nil
}

// ServeHTTP is the main middleware handler entry point.
func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.mode == RewriteMode {
		m.handleRewrite(w, r)
	} else if m.mode == CheckMode {
		m.handleCheck(w, r)
	}
}
