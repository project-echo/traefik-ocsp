package traefik_ocsp //nolint:all

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func (m *middleware) handleRewrite(w http.ResponseWriter, r *http.Request) {
	var prefix string
	found := false
	// Look for specific path prefixes first
	for _, p := range m.pathPrefixes {
		if strings.HasPrefix(r.URL.Path, p) {
			prefix = p
			found = true
			break
		}
	}

	// No specific match and regex is defined
	if len(prefix) == 0 && m.pathRegexp != nil {
		match := m.pathRegexp.Find([]byte(r.URL.Path))
		if match != nil {
			prefix = string(match)
			found = true
		}
	}

	// If not interesting path for us, continue
	if !found {
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
	pathData, ok := strings.CutPrefix(r.URL.Path, prefix+"/")
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
	r.URL.Path = prefix
	r.RequestURI = prefix
	r.Header.Set("Content-Type", "application/ocsp-request")
	r.Header.Set("Content-Length", strconv.Itoa(len(data)))
	r.ContentLength = int64(len(data))
	r.Body = io.NopCloser(bytes.NewReader(data))

	m.next.ServeHTTP(w, r)
}
