package traefik_ocsp_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logfmt/logfmt"
	plug "github.com/project-echo/traefik-ocsp"
)

type payload struct {
	prefix  string
	payload string
	bytes   []byte
}

var (
	clientPEM, _ = os.ReadFile("./test/pki/ocsptest_good.crt") //nolint:all
	issuerPEM, _ = os.ReadFile("./test/pki/intermediate_ca.crt") //nolint:all
)

func TestInvalidModeConfig(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Mode = "wrong"

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := plug.New(ctx, next, cfg, "ocsp")

	if !errors.Is(err, plug.ErrInvalidMode) {
		t.Errorf("Mode was wrong, should have returned error")
	}
}

func TestInvalidEndpointConfig(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Mode = plug.CheckMode
	cfg.Issuers = []plug.IssuerConfig{
		{
			OCSPEndpoint: "mailto:invalid",
			IssuerPEM:    "",
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := plug.New(ctx, next, cfg, "ocsp")

	if !errors.Is(err, plug.ErrInvalidEndpoint) {
		t.Errorf("Endpoint URL was invalid, should have returned error")
	}
}

func TestInvalidCertConfig(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Mode = plug.CheckMode
	cfg.Issuers = []plug.IssuerConfig{
		{
			OCSPEndpoint: "https://example.com/ocsp",
			IssuerPEM:    "",
		},
	}

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := plug.New(ctx, next, cfg, "ocsp")

	if !errors.Is(err, plug.ErrInvalidCertificate) {
		t.Errorf("Issuer PEM was invalid, should have returned error")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := plug.CreateConfig()

	for _, prefix := range cfg.Rewrite.PathPrefixes {
		testPayloads(t, cfg, prefix)
	}
}

func TestMultiPathConfig(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Mode = plug.RewriteMode
	cfg.Rewrite.PathPrefixes = []string{"/v1/pki_one/ocsp", "/v1/pki_two/ocsp"}

	for _, prefix := range cfg.Rewrite.PathPrefixes {
		testPayloads(t, cfg, prefix)
	}
}

func TestPathRegexConfig(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Mode = plug.RewriteMode
	cfg.Rewrite.PathPrefixes = []string{"/ocsp"}
	cfg.Rewrite.PathRegexp = `^/v1/[^/]+/(unified-)?ocsp`

	prefixes := []string{"/ocsp", "/v1/pki_one/ocsp", "/v1/pki_two/unified-ocsp"}

	for _, prefix := range prefixes {
		testPayloads(t, cfg, prefix)
	}
}

func TestInvalidRegexConfig(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Rewrite.PathRegexp = `[`

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	_, err := plug.New(ctx, next, cfg, "ocsp")

	if !errors.Is(err, plug.ErrInvalidRegexp) {
		t.Errorf("Regexp was invalid, should have returned error")
	}
}

func TestNoPrefixMatch(t *testing.T) {
	cfg := plug.CreateConfig()
	cfg.Mode = plug.RewriteMode
	cfg.Rewrite.PathPrefixes = []string{"/ocsp"}
	cfg.Rewrite.PathRegexp = `^/v1/[^/]+/ocsp`

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	path := "/non-matching-path"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if req.Method != http.MethodGet {
		t.Errorf("req.Method = %s; want GET", req.Method)
	}

	if req.URL.Path != path {
		t.Errorf("req.URL.Path = %s; want %s", req.URL.Path, path)
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("recorder.Code = %d; want %d", recorder.Code, http.StatusOK)
	}
}

func TestBadMethod(t *testing.T) {
	cfg := plug.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "http://localhost/ocsp", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("recorder.Code = %d; want %d", recorder.Code, http.StatusMethodNotAllowed)
	}

	msg := "Expecting GET or POST requests only\n"
	if recorder.Body.String() != msg {
		t.Errorf("recorder.Body = %s; want %s", recorder.Body.String(), msg)
	}
}

func TestMissingPayload(t *testing.T) {
	cfg := plug.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/ocsp", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("recorder.Code = %d; want %d", recorder.Code, http.StatusBadRequest)
	}

	msg := "Invalid request path\n"
	if recorder.Body.String() != msg {
		t.Errorf("recorder.Body = %s; want %s", recorder.Body.String(), msg)
	}
}

func TestBadPayload(t *testing.T) {
	cfg := plug.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/ocsp/bad-data", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("recorder.Code = %d; want %d", recorder.Code, http.StatusBadRequest)
	}

	msg := "Invalid request data\n"
	if recorder.Body.String() != msg {
		t.Errorf("recorder.Body = %s; want %s", recorder.Body.String(), msg)
	}
}

func TestCheckHandlerMissingTLS(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	cfg, infoBuf, _ := createCheckConfig()
	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Errorf("invalid handler setup: %s", err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// TLS but without client cert
	req.TLS = &tls.ConnectionState{}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		body, _ := io.ReadAll(recorder.Body)
		t.Errorf("recorder.Code = %d; want %d -- %s", recorder.Code, http.StatusOK, body)
	}

	msg := "Request is not using TLS or client certificate is missing"
	if !strings.Contains(infoBuf.String(), msg) {
		t.Errorf("Expected message in logs: '%s', got: '%s'", msg, infoBuf.String())
	}
}

func TestCheckHandlerNoMatch(t *testing.T) {
	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	cfg, infoBuf, _ := createCheckConfig()
	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Errorf("invalid handler setup: %s", err.Error())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := pemToCert(clientPEM)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		body, _ := io.ReadAll(recorder.Body)
		t.Errorf("recorder.Code = %d; want %d -- %s", recorder.Code, http.StatusOK, body)
	}

	msg := "No matching OCSP issuer was checked"
	if !strings.Contains(infoBuf.String(), msg) {
		t.Errorf("Expected message in logs: '%s', got: '%s'", msg, infoBuf.String())
	}
}

//////////////////////////////////////////////////////////////////////////

func createTestPayloads(prefix string) map[string]payload {
	return map[string]payload{
		"without slashes": {
			prefix:  prefix,
			payload: "MFUwUzBRME8wTTAJBgUrDgMCGgUABBT3O18PnpuclNZtpOrVxflCqr5EhAQUpAUtGSmhUlvQrdQvR22AQcL1TkICFATjZCxaxNrh6M4oUoMxQ6O0hW24",
			bytes: []byte{
				0x30, 0x55, 0x30, 0x53, 0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
				0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0xf7, 0x3b, 0x5f, 0x0f, 0x9e, 0x9b, 0x9c, 0x94, 0xd6,
				0x6d, 0xa4, 0xea, 0xd5, 0xc5, 0xf9, 0x42, 0xaa, 0xbe, 0x44, 0x84, 0x04, 0x14, 0xa4, 0x05, 0x2d,
				0x19, 0x29, 0xa1, 0x52, 0x5b, 0xd0, 0xad, 0xd4, 0x2f, 0x47, 0x6d, 0x80, 0x41, 0xc2, 0xf5, 0x4e,
				0x42, 0x02, 0x14, 0x04, 0xe3, 0x64, 0x2c, 0x5a, 0xc4, 0xda, 0xe1, 0xe8, 0xce, 0x28, 0x52, 0x83,
				0x31, 0x43, 0xa3, 0xb4, 0x85, 0x6d, 0xb8,
			},
		},
		"with slashes": {
			prefix:  prefix,
			payload: "MFUwUzBRME8wTTAJBgUrDgMCGgUABBT3O18PnpuclNZtpOrVxflCqr5EhAQUpAUtGSmhUlvQrdQvR22AQcL1TkICFFJrnVz4T93oc55//y83KISdFI8z",
			bytes: []byte{
				0x30, 0x55, 0x30, 0x53, 0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
				0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0xf7, 0x3b, 0x5f, 0x0f, 0x9e, 0x9b, 0x9c, 0x94, 0xd6,
				0x6d, 0xa4, 0xea, 0xd5, 0xc5, 0xf9, 0x42, 0xaa, 0xbe, 0x44, 0x84, 0x04, 0x14, 0xa4, 0x05, 0x2d,
				0x19, 0x29, 0xa1, 0x52, 0x5b, 0xd0, 0xad, 0xd4, 0x2f, 0x47, 0x6d, 0x80, 0x41, 0xc2, 0xf5, 0x4e,
				0x42, 0x02, 0x14, 0x52, 0x6b, 0x9d, 0x5c, 0xf8, 0x4f, 0xdd, 0xe8, 0x73, 0x9e, 0x7f, 0xff, 0x2f,
				0x37, 0x28, 0x84, 0x9d, 0x14, 0x8f, 0x33,
			},
		},
	}
}

func testPayloads(t *testing.T, cfg *plug.Config, prefix string) {
	t.Helper()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := plug.New(ctx, next, cfg, "ocsp")
	if err != nil {
		t.Fatal(err)
	}

	tests := createTestPayloads(prefix)

	for name, payload := range tests {
		t.Run(name+" on "+payload.prefix, func(t *testing.T) {
			assertOcspRequest(t, handler, payload)
		})
	}
}

func assertOcspRequest(t *testing.T, handler http.Handler, p payload) {
	t.Helper()

	ctx := context.Background()
	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+p.prefix+"/"+p.payload, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if req.Method != http.MethodPost {
		t.Errorf("req.Method = %s; want POST", req.Method)
	}

	if req.URL.Path != p.prefix {
		t.Errorf("req.URL.Path = %s; want %s", req.URL.Path, p.prefix)
	}

	if req.RequestURI != p.prefix {
		t.Errorf("req.RequestURI = %s; want %s", req.RequestURI, p.prefix)
	}

	contentLength := int64(len(p.bytes))
	if req.ContentLength != contentLength {
		t.Errorf("req.ContentLength = %d; want %d", req.ContentLength, contentLength)
	}

	assertHeader(t, req, "Content-Type", "application/ocsp-request")
	assertHeader(t, req, "Content-Length", strconv.FormatInt(contentLength, 10))

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Errorf("could not read body: %s", err.Error())
	}

	if !bytes.Equal(p.bytes, bodyBytes) {
		t.Errorf("unexpected payload: %v -- expected: %v", bodyBytes, p.bytes)
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s, expected: %s", req.Header.Get(key), expected)
	}
}

func pemToCert(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func overrideEncoders(cfg *plug.Config) (*bytes.Buffer, *bytes.Buffer) {
	infoBuf := new(bytes.Buffer)
	errorBuf := new(bytes.Buffer)

	cfg.InfoEncoder = logfmt.NewEncoder(infoBuf)
	cfg.ErrorEncoder = logfmt.NewEncoder(errorBuf)

	return infoBuf, errorBuf
}

//nolint:unparam // errBuf not yet used in tests, but can be to check internal error handling
func createCheckConfig() (*plug.Config, *bytes.Buffer, *bytes.Buffer) {
	cfg := plug.CreateConfig()
	cfg.Mode = plug.CheckMode
	cfg.Issuers = []plug.IssuerConfig{
		{
			OCSPEndpoint: "https://httpbin.org/anything",
			IssuerPEM:    string(issuerPEM),
		},
	}
	infoBuf, errBuf := overrideEncoders(cfg)
	return cfg, infoBuf, errBuf
}
