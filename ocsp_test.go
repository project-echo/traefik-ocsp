package traefik_ocsp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	plug "github.com/project-echo/traefik-ocsp"
)

func TestDemo(t *testing.T) {
	cfg := plug.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	handler, err := plug.New(ctx, next, cfg, "traefik-ocsp")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	payload := "MFUwUzBRME8wTTAJBgUrDgMCGgUABBT3O18PnpuclNZtpOrVxflCqr5EhAQUpAUtGSmhUlvQrdQvR22AQcL1TkICFFJrnVz4T93oc55//y83KISdFI8z"
	payloadBytes := []byte{
		0x30, 0x55, 0x30, 0x53, 0x30, 0x51, 0x30, 0x4f, 0x30, 0x4d, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
		0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0xf7, 0x3b, 0x5f, 0x0f, 0x9e, 0x9b, 0x9c, 0x94, 0xd6,
		0x6d, 0xa4, 0xea, 0xd5, 0xc5, 0xf9, 0x42, 0xaa, 0xbe, 0x44, 0x84, 0x04, 0x14, 0xa4, 0x05, 0x2d,
		0x19, 0x29, 0xa1, 0x52, 0x5b, 0xd0, 0xad, 0xd4, 0x2f, 0x47, 0x6d, 0x80, 0x41, 0xc2, 0xf5, 0x4e,
		0x42, 0x02, 0x14, 0x52, 0x6b, 0x9d, 0x5c, 0xf8, 0x4f, 0xdd, 0xe8, 0x73, 0x9e, 0x7f, 0xff, 0x2f,
		0x37, 0x28, 0x84, 0x9d, 0x14, 0x8f, 0x33,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/ocsp/"+payload, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	if req.Method != http.MethodPost {
		t.Errorf("req.Method = %s; want POST", req.Method)
	}

	if req.URL.Path != cfg.PathPrefix {
		t.Errorf("req.URL.Path = %s; want %s", req.URL.Path, cfg.PathPrefix)
	}

	assertHeader(t, req, "Content-Type", "application/ocsp-request")

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Errorf("could not read body: %s", err.Error())
	}

	if !bytes.Equal(payloadBytes, bodyBytes) {
		t.Errorf("unexpected payload: %v -- expected: %v", bodyBytes, payloadBytes)
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s, expected: %s", req.Header.Get(key), expected)
	}
}
