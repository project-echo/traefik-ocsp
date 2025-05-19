package util

import (
	"bytes"
	"fmt"

	"github.com/project-echo/traefik-ocsp/internal/ocsp"
)

func HexFormatted(buf []byte) string {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			fmt.Fprint(&ret, ":")
		}
		fmt.Fprintf(&ret, "%02x", cur)
	}
	return ret.String()
}

func StatusString(status int) string {
	if status == ocsp.Good {
		return "Good"
	}
	if status == ocsp.Revoked {
		return "Revoked"
	}
	if status == ocsp.ServerFailed {
		return "ServerFailed"
	}
	return "Unknown"
}

func RevocationReasonString(reason int) string {
	if reason == ocsp.Unspecified {
		return "Unspecified"
	}
	if reason == ocsp.KeyCompromise {
		return "KeyCompromise"
	}
	if reason == ocsp.CACompromise {
		return "CACompromise"
	}
	if reason == ocsp.AffiliationChanged {
		return "AffiliationChanged"
	}
	if reason == ocsp.Superseded {
		return "Superseded"
	}
	if reason == ocsp.CessationOfOperation {
		return "CessationOfOperation"
	}
	if reason == ocsp.CertificateHold {
		return "CertificateHold"
	}
	if reason == ocsp.RemoveFromCRL {
		return "RemoveFromCRL"
	}
	if reason == ocsp.PrivilegeWithdrawn {
		return "PrivilegeWithdrawn"
	}
	if reason == ocsp.AACompromise {
		return "AACompromise"
	}
	return "Unknown"
}
