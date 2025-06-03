package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	GOOD_SERIAL = certSerial(loadCertificate("./pki/ocsptest_good.crt"))
	UNKNOWN_SERIAL = certSerial(loadCertificate("./pki/ocsptest_unknown.crt"))
	REVOKED_SERIAL = certSerial(loadCertificate("./pki/ocsptest_revoked.crt"))
	ERROR_SERIAL = certSerial(loadCertificate("./pki/ocsptest_invalid.crt"))
)

func main() {
	http.HandleFunc("/ocsp", handleRequest)
	log.Println("Starting OCSP fixture server on :80")
	log.Fatal(http.ListenAndServe(":80", nil))
}

var privateKey = loadKey("./pki/clientauth_ca.key")
var caCert = loadCertificate("./pki/clientauth_ca.crt")

func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received OCSP request from %s\n", r.RemoteAddr)

	data, err := io.ReadAll(r.Body)
	if (err != nil) {
		log.Printf("Could not read body! %s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ocspReq, err := ocsp.ParseRequest(data)
	if (err != nil) {
		log.Printf("Not a valid OCSPRequest! %s\n", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

    serial := hexFormatted(ocspReq.SerialNumber.Bytes())

	if serial == GOOD_SERIAL {
		handleResponse(w, r, ocspReq, ocsp.Good)
	} else if serial == REVOKED_SERIAL {
		handleResponse(w, r, ocspReq, ocsp.Revoked)
	} else if serial == UNKNOWN_SERIAL {
		handleResponse(w, r, ocspReq, ocsp.Unknown)
	} else if serial == ERROR_SERIAL {
		handleError(w, r)
	} else {
		log.Printf("Not a known testing cert serial! %s\n", ocspReq.SerialNumber)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func handleResponse(w http.ResponseWriter, _ *http.Request, ocspReq *ocsp.Request, status int) {
	w.Header().Add("Content-type", "application/ocsp-response")

	template := ocsp.Response{
		Status: status,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(2 * time.Hour),
	}
	if status == ocsp.Revoked {
		template.RevokedAt = time.Now().Add(-2 * time.Hour)
		template.RevocationReason = ocsp.Unspecified
	}

	ocspResponse, err := ocsp.CreateResponse(caCert, caCert, template, privateKey)
	if err != nil {
		log.Printf("Failed to create OCSP response! %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	w.Write(ocspResponse)
}

func handleError(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-type", "application/ocsp-response")
	w.Write(ocsp.InternalErrorErrorResponse)
}

func hexFormatted(buf []byte) string {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			fmt.Fprint(&ret, ":")
		}
		fmt.Fprintf(&ret, "%02x", cur)
	}
	return ret.String()
}

func loadCertificate(certFile string) (*x509.Certificate) {
    certPEM, err := os.ReadFile(certFile)
    if err != nil {
        panic(fmt.Sprintf("Failed to read certificate file: %v", err))
    }
    block, _ := pem.Decode(certPEM)
    if block == nil || block.Type != "CERTIFICATE" {
        panic("Failed to decode PEM block containing certificate")
    }
    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        panic(fmt.Sprintf("Failed to parse certificate: %v", err))
    }
	return cert
}

func loadKey(keyFile string) (*rsa.PrivateKey) {
    keyBytes, err := os.ReadFile(keyFile)
    if err != nil {
        panic(fmt.Sprintf("failed to read file: %v", err))
    }
    block, _ := pem.Decode(keyBytes)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        panic("Failed to decode PEM block containing RSA private key")
    }
    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        panic(fmt.Sprintf("Failed to parse RSA private key: %v", err))
    }
    return privateKey
}

func certSerial(cert *x509.Certificate) string {
    serial := hexFormatted(cert.SerialNumber.Bytes())
	return serial;
}
