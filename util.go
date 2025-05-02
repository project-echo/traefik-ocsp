package traefik_ocsp //nolint:all

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/go-logfmt/logfmt"
	"github.com/project-echo/traefik-ocsp/internal/ocsp"
)

var (
	infoEncoder  = logfmt.NewEncoder(os.Stdout)
	errorEncoder = logfmt.NewEncoder(os.Stderr)
)

func (m *middleware) logDebug(keyvals []interface{}) {
	err := infoEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "debug",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	infoEncoder.EndRecord()
}

func (m *middleware) logInfo(keyvals []interface{}) {
	err := infoEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "info",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	infoEncoder.EndRecord()
}

func (m *middleware) logError(keyvals []interface{}) {
	err := errorEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "error",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	errorEncoder.EndRecord()
}

func kv(keyvals ...interface{}) []interface{} {
	return keyvals
}

func getHexFormatted(buf []byte) string {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			fmt.Fprint(&ret, ":")
		}
		fmt.Fprintf(&ret, "%02x", cur)
	}
	return ret.String()
}

func statusString(status int) string {
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

func revocationReasonString(reason int) string {
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
