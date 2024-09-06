// Package ocsp is a plugin to convert OCSP check GET requests to POST.
package ocsp

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

// Config holds the plugin configuration.
type Config struct {
	PathPrefix string
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{
		PathPrefix: "/ocsp",
	}
}

type middleware struct {
	next       http.Handler
	name       string
	pathPrefix string
}

// New creates and returns a new ocsp plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &middleware{
		next:       next,
		pathPrefix: config.PathPrefix,
		name:       name,
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If not interesting path for us, continue
	if !strings.HasPrefix(r.URL.Path, m.pathPrefix) {
		m.next.ServeHTTP(w, r)
		return
	}

	// Already a POST, continue
	if r.Method == http.MethodPost {
		m.next.ServeHTTP(w, r)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Expecting GET or POST requests only", http.StatusMethodNotAllowed)
		return
	}

	// Get the base64-encoded part from end of URL path
	prefix := m.pathPrefix + "/"
	pathData, ok := strings.CutPrefix(r.URL.Path, prefix)
	if !ok {
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}

	// Convert to original binary DER-encoded data
	data, err := base64.StdEncoding.DecodeString(pathData)
	if err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Re-format to POST request a per RFC6960
	// See https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1
	r.Method = http.MethodPost
	r.URL.Path = m.pathPrefix
	r.Header.Set("Content-Type", "application/ocsp-request")
	r.Body = io.NopCloser(bytes.NewReader(data))

	m.next.ServeHTTP(w, r)
}
