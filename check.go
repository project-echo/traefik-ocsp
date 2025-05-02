package traefik_ocsp //nolint:all

import (
	"bytes"
	"fmt"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	// forked "golang.org/x/crypto/ocsp"
	"github.com/project-echo/traefik-ocsp/internal/ocsp"
)

func (m *middleware) handleCheck(w http.ResponseWriter, r *http.Request) {
	// Only works with client cert auth
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		m.logInfo(kv(
			"msg", "Request is not using TLS or client certificate is missing",
			"tls", (r.TLS != nil),
		))
		http.Error(w, "Client certificate authentication is required", http.StatusForbidden)
		return
	}

	checked := false

	for _, cert := range r.TLS.PeerCertificates {
		// Look up configured issuer cert by the authority key ID
		authKeyID := getHexFormatted(cert.AuthorityKeyId)
		issuer, ok := m.issuers[authKeyID]
		if !ok {
			continue
		}

		ocspReq, err := ocsp.CreateRequest(cert, issuer.issuerCert, nil)
		if err != nil {
			m.logError(kv(
				"msg", "OCSP request creation failed",
				"serial", getHexFormatted(cert.SerialNumber.Bytes()),
				"issuer", getHexFormatted(issuer.issuerCert.SubjectKeyId),
				"error", err.Error(),
			))
			http.Error(w, "Client verification failed (bad request)", http.StatusInternalServerError)
			return
		}

		m.logInfo(kv(
			"msg", "Sending OCSP request",
			"url", issuer.ocspEndpoint,
			"serial", getHexFormatted(cert.SerialNumber.Bytes()),
		))

		ocspRes, err := m.client.Post(
			issuer.ocspEndpoint,
			"application/ocsp-request",
			bytes.NewReader(ocspReq),
		)
		if err != nil {
			m.logError(kv(
				"msg", "Request to OCSP endpoint failed",
				"url", issuer.ocspEndpoint,
				"error", err.Error(),
			))
			http.Error(w, "Client verification failed (bad response)", http.StatusInternalServerError)
			return
		}
		if ocspRes.StatusCode != http.StatusOK {
			m.logError(kv(
				"msg", "Request to OCSP endpoint failed",
				"url", issuer.ocspEndpoint,
				"status", ocspRes.Status,
			))
			http.Error(w, "Client verification failed (bad response)", http.StatusInternalServerError)
			return
		}
		ocspBytes, err := io.ReadAll(ocspRes.Body)
		if err != nil {
			m.logError(kv(
				"msg", "Failed to read OCSP endpoint response",
				"url", issuer.ocspEndpoint,
				"error", err.Error(),
			))
			http.Error(w, "Client verification failed (body read fail)", http.StatusInternalServerError)
			return
		}
		ocspResponse, err := ocsp.ParseResponse(ocspBytes, issuer.issuerCert)
		if err != nil {
			m.logError(kv(
				"msg", "Failed to parse OCSP response",
				"url", issuer.ocspEndpoint,
				"error", err.Error(),
			))
			http.Error(w, "Client verification failed (ocsp response fail)", http.StatusInternalServerError)
			return
		}

		if m.debug {
			m.logDebug(kv(
				"msg", "Base64 formatted OCSP request",
				"data", base64.StdEncoding.EncodeToString(ocspReq),
			))
			m.logDebug(kv(
				"msg", "Base64 formatted OCSP response",
				"data", base64.StdEncoding.EncodeToString(ocspBytes),
			))
			m.logDebug(kv(
				"msg", "OCSP response struct",
				"data", fmt.Sprintf("%+v", ocspResponse),
			))
		}

		// Only reject if cert is revoked (pass on Good/Unknown)
		if ocspResponse.Status == ocsp.Revoked {
			m.logInfo(kv(
				"msg", "Client certificate is revoked",
				"cn", cert.Subject.CommonName,
				"serial", getHexFormatted(cert.SerialNumber.Bytes()),
				"status", statusString(ocspResponse.Status),
				"reason", revocationReasonString(ocspResponse.RevocationReason),
				"revokedat", ocspResponse.RevokedAt.Format(time.RFC3339Nano),
			))
			http.Error(w, "Client certificate has been revoked", http.StatusForbidden)
			return
		}

		m.logInfo(kv(
			"msg", "OCSP response status",
			"url", issuer.ocspEndpoint,
			"cn", cert.Subject.CommonName,
			"serial", getHexFormatted(cert.SerialNumber.Bytes()),
			"status", statusString(ocspResponse.Status),
			"producedat", ocspResponse.ProducedAt.Format(time.RFC3339Nano),
			"thisupdate", ocspResponse.ThisUpdate.Format(time.RFC3339Nano),
			"nextupdate", ocspResponse.NextUpdate.Format(time.RFC3339Nano),
			"revokedat", ocspResponse.RevokedAt.Format(time.RFC3339Nano),
		))

		checked = true
	}

	if !checked {
		m.logInfo(kv(
			"msg", "No matching OCSP issuer was checked",
			"certs", len(r.TLS.PeerCertificates),
		))
	}

	// Continues if no configured issuers found or found cert was not revoked
	m.next.ServeHTTP(w, r)
}
