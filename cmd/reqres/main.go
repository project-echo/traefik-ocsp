// Package main is a command-line tool for parsing OCSP requests and responses, and checking certificate revocation status.
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/project-echo/traefik-ocsp/internal/ocsp"
	"github.com/project-echo/traefik-ocsp/internal/util"
)

//
// This is a OCSP request and response parser and OCSP revocation check tool.
//
// Example usage:
//
//   go run ./cmd/reqres/main.go request ocsp_request.der
//   go run ./cmd/reqres/main.go response ocsp_response.der issuer_cert.pem
//   go run ./cmd/reqres/main.go check client_cert.pem issuer_cert.pem
//

//nolint:gocyclo
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Not enough arguments!")
		os.Exit(1)
	}

	mode := os.Args[1]

	if mode != "request" && mode != "response" && mode != "check" {
		fmt.Println("Unsupported mode parameter!")
		os.Exit(1)
	}

	// Read OCSP request as binary blob and print it
	if mode == "request" {
		if len(os.Args) < 2 {
			fmt.Println("Not enough arguments!")
			os.Exit(1)
		}
		payloadPath, err := validatePath(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid payload path: %s\n", err.Error())
			os.Exit(1)
		}
		handleRequest(payloadPath)
	}

	// Read OCSP request as binary blob with issuer cert PEM and print it
	if mode == "response" {
		if len(os.Args) < 3 {
			fmt.Println("Not enough arguments!")
			os.Exit(1)
		}
		payloadPath, err := validatePath(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid payload path: %s\n", err.Error())
			os.Exit(1)
		}
		issuerPath, err := validatePath(os.Args[3])
		if err != nil {
			fmt.Printf("Invalid payload path: %s\n", err.Error())
			os.Exit(1)
		}
		handleResponse(payloadPath, issuerPath)
	}

	// Read client and issuer certs and do OCSP revocation check
	if mode == "check" {
		if len(os.Args) < 3 {
			fmt.Println("Not enough arguments!")
			os.Exit(1)
		}
		certPath, err := validatePath(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid payload path: %s\n", err.Error())
			os.Exit(1)
		}
		issuerPath, err := validatePath(os.Args[3])
		if err != nil {
			fmt.Printf("Invalid payload path: %s\n", err.Error())
			os.Exit(1)
		}
		handleCheck(certPath, issuerPath)
	}
}

func handleRequest(payloadPath string) {
	data, err := os.ReadFile(filepath.Clean(payloadPath))
	if err != nil {
		fmt.Printf("Can not read payload file! %s\n", err.Error())
		os.Exit(1)
	}

	req, err := ocsp.ParseRequest(data)
	if err != nil {
		fmt.Printf("Not a valid OCSPRequest! %s\n", err.Error())
		os.Exit(1)
	}

	printOCSPRequest(req)
}

func handleResponse(payloadPath, issuerPath string) {
	data, err := os.ReadFile(filepath.Clean(payloadPath))
	if err != nil {
		fmt.Printf("Can not read payload file! %s\n", err.Error())
		os.Exit(1)
	}

	pemData, err := os.ReadFile(filepath.Clean(issuerPath))
	if err != nil {
		fmt.Println("Issuer cert could not be read!")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	pemBlock, _ := pem.Decode(pemData)
	certBytes := pemBlock.Bytes
	issuerCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Println("Issuer cert file is not valid!")
		os.Exit(1)
	}

	res, err := ocsp.ParseResponse(data, issuerCert)
	if err != nil {
		fmt.Printf("Not a valid OCSPResponse! %s\n", err.Error())
		os.Exit(1)
	}

	printOCSPResponse(res)
}

func handleCheck(certPath, issuerPath string) {
	cert := readCert(certPath)
	issuerCert := readCert(issuerPath)

	ocspReq, err := ocsp.CreateRequest(cert, issuerCert, nil)
	if err != nil {
		fmt.Printf("Could not create OCSP request: %s\n", err.Error())
		os.Exit(1)
	}
	req, err := ocsp.ParseRequest(ocspReq)
	if err != nil {
		fmt.Printf("Not a valid OCSPRequest! %s\n", err.Error())
		os.Exit(1)
	}

	printOCSPRequest(req)

	ocspID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	caIssuerID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

	extensions := getAuthorityInformationAccessData(cert)

	fmt.Printf("\nCertificate authority extensions:\n")
	fmt.Printf("  OCSP: %s\n", extensions[ocspID.String()])
	fmt.Printf("  CA:   %s\n", extensions[caIssuerID.String()])

	fmt.Printf("\nBase64 formatted request:\n\n%s\n\n", base64.StdEncoding.EncodeToString(ocspReq))

	ocspEndpoint, _ := url.Parse(extensions[ocspID.String()])
	ocspEndpoint.Scheme = "https"

	client := &http.Client{}

	ocspRes, err := client.Post(
		ocspEndpoint.String(),
		"application/ocsp-request",
		bytes.NewReader(ocspReq),
	)
	if err != nil {
		slog.Error(
			"Request to OCSP endpoint failed",
			"url", ocspEndpoint,
			"error", err.Error(),
		)
		return
	}
	if ocspRes.StatusCode != http.StatusOK {
		slog.Error(
			"Request to OCSP endpoint failed",
			"url", ocspEndpoint,
			"status", ocspRes.Status,
		)
		return
	}
	ocspBytes, err := io.ReadAll(ocspRes.Body)
	if err != nil {
		slog.Error(
			"Failed to read OCSP endpoint response",
			"url", ocspEndpoint,
			"error", err.Error(),
		)
		return
	}

	fmt.Printf("Base64 formatted response:\n\n%s\n\n", base64.StdEncoding.EncodeToString(ocspBytes))

	ocspResponse, err := ocsp.ParseResponse(ocspBytes, issuerCert)
	if err != nil {
		slog.Error(
			"Failed to parse OCSP response",
			"url", ocspEndpoint,
			"error", err.Error(),
		)
		return
	}

	if ocspResponse.Status == ocsp.Revoked {
		slog.Error("Certificate has been revoked!")
	}

	printOCSPResponse(ocspResponse)
}

// ErrInvalidFilePath is returned when the file path is not valid (under working directory).
var ErrInvalidFilePath = errors.New("invalid path used")

func validatePath(userInput string) (string, error) {
	cleanPath := filepath.Clean(userInput)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", err
	}

	baseDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absPath, baseDir) {
		return "", ErrInvalidFilePath
	}

	return absPath, nil
}

func getAuthorityInformationAccessData(cert *x509.Certificate) map[string]string {
	result := make(map[string]string)

	// Authority Information Access
	// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.1
	extID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	// Example structure:
	// $ dumpasn1 cert_ext_asn1.dump
	//   0 134: SEQUENCE {
	//   3  66:   SEQUENCE {
	//   5   8:     OBJECT IDENTIFIER ocsp (1 3 6 1 5 5 7 48 1)
	//  15  54:     [6]
	//        :       'http://vault.example.com/v1/pki_test/ocsp'
	//        :     }
	//  71  64:   SEQUENCE {
	//  73   8:     OBJECT IDENTIFIER caIssuers (1 3 6 1 5 5 7 48 2)
	//  83  52:     [6]
	//        :       'http://vault.example.com/v1/pki_test/ca'
	//        :     }
	//        :   }

	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(extID) {
			continue
		}
		var raw []asn1.RawValue
		_, _ = asn1.Unmarshal(ext.Value, &raw)

		for _, val := range raw {
			var rawval asn1.RawValue
			var inner []asn1.RawValue
			var id asn1.ObjectIdentifier
			var value asn1.RawValue
			_, _ = asn1.Unmarshal(val.FullBytes, &rawval)
			_, _ = asn1.Unmarshal(rawval.FullBytes, &inner)
			_, _ = asn1.Unmarshal(inner[0].FullBytes, &id)
			_, _ = asn1.Unmarshal(inner[1].FullBytes, &value)
			result[id.String()] = string(value.Bytes)
		}
	}

	return result
}

func printOCSPRequest(req *ocsp.Request) {
	fmt.Println("OCSP request:")
	fmt.Printf("  SerialNumber: %s\n", util.HexFormatted(req.SerialNumber.Bytes()))
	fmt.Printf("  HashAlgorithm: %s\n", req.HashAlgorithm)
	fmt.Printf("  IssuerNameHash: %s\n", hex.EncodeToString(req.IssuerNameHash))
	fmt.Printf("  IssuerKeyHash: %v\n", hex.EncodeToString(req.IssuerKeyHash))
}

func printOCSPResponse(res *ocsp.Response) {
	fmt.Println("OCSP response:")
	fmt.Printf("  SerialNumber: %s\n", util.HexFormatted(res.SerialNumber.Bytes()))
	fmt.Printf("  Status: %d (%s)\n", res.Status, util.StatusString(res.Status))
	fmt.Printf("  Revocation reason: %d (%s)\n", res.RevocationReason, util.RevocationReasonString(res.RevocationReason))
	if len(res.RawResponderName) > 0 {
		fmt.Printf("  RawResponderName: %v\n", strings.ReplaceAll(string(res.RawResponderName), "\n", " "))
	}
	if len(res.ResponderKeyHash) > 0 {
		fmt.Printf("  ResponderKeyHash: %v\n", hex.EncodeToString(res.ResponderKeyHash))
	}
	fmt.Printf("  ProducedAt: %s\n", res.ProducedAt.Format(time.RFC3339Nano))
	fmt.Printf("  ThisUpdate: %s\n", res.ThisUpdate.Format(time.RFC3339Nano))
	fmt.Printf("  NextUpdate: %s\n", res.NextUpdate.Format(time.RFC3339Nano))
	fmt.Printf("  RevokedAt:  %s\n", res.RevokedAt.Format(time.RFC3339Nano))
}

func readCert(path string) *x509.Certificate {
	pemData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		fmt.Printf("Cert could not be read on path '%s': %s\n", path, err.Error())
		os.Exit(1)
	}
	pemBlock, _ := pem.Decode(pemData)
	certBytes := pemBlock.Bytes
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		fmt.Printf("Cert file is not valid: %s\n", err.Error())
		os.Exit(1)
	}
	return cert
}
