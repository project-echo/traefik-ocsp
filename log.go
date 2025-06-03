// Package traefik_ocsp is a plugin to integrate OCSP checks as Traefik middleware.
//
// This file implements the logging methods for the middleware, using logfmt as
// the output format.
package traefik_ocsp //nolint:all

import (
	"fmt"
	"os"
	"time"
)

func (m *middleware) logDebug(keyvals []interface{}) {
	if m.logLevel != "debug" {
		return
	}
	err := m.infoEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "debug",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	_ = m.infoEncoder.EndRecord()
}

func (m *middleware) logInfo(keyvals []interface{}) {
	if m.logLevel == "error" {
		return
	}
	err := m.infoEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "info",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	_ = m.infoEncoder.EndRecord()
}

func (m *middleware) logError(keyvals []interface{}) {
	err := m.errorEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "error",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stderr.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	_ = m.errorEncoder.EndRecord()
}

func kv(keyvals ...interface{}) []interface{} {
	return keyvals
}
