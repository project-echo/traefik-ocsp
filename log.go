package traefik_ocsp //nolint:all

import (
	"fmt"
	"os"
	"time"
)

func (m *middleware) logDebug(keyvals []interface{}) {
	err := m.infoEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "debug",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	m.infoEncoder.EndRecord()
}

func (m *middleware) logInfo(keyvals []interface{}) {
	err := m.infoEncoder.EncodeKeyvals(append(kv(
		"time", time.Now().Format(time.RFC3339Nano),
		"level", "info",
		"middlewareName", m.name,
	), keyvals...)...)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("[%s] logger error: %s\n", m.name, err.Error())) //nolint:all
	}
	m.infoEncoder.EndRecord()
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
	m.errorEncoder.EndRecord()
}

func kv(keyvals ...interface{}) []interface{} {
	return keyvals
}
