package main

import (
	"bytes"
	"crypto/rand"
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
	GOOD_SERIAL = "1f:ac:db:ac:f6:aa:26:1e:fe:a7:90:bf:fd:13:a4:25:74:62:a2:7e"
	UNKNOWN_SERIAL = "1f:ac:db:ac:f6:aa:26:1e:fe:a7:90:bf:fd:13:a4:25:74:62:a2:7f"
	REVOKED_SERIAL = "1f:ac:db:ac:f6:aa:26:1e:fe:a7:90:bf:fd:13:a4:25:74:62:a2:80"
	ERROR_SERIAL = "1f:ac:db:ac:f6:aa:26:1e:fe:a7:90:bf:fd:13:a4:25:74:62:a2:7a"
)

func main() {
	http.HandleFunc("/ocsp", handleRequest)
	log.Println("Starting OCSP fixture server on :8089")
	log.Fatal(http.ListenAndServe(":8089", nil))
}

var privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
var caCert = loadCertificate("./pki/intermediate_ca.crt")

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
