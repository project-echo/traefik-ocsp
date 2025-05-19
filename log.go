package traefik_ocsp //nolint:all

import (
	"fmt"
	"os"
	"time"

	"github.com/go-logfmt/logfmt"
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
