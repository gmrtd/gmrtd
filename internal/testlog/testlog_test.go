package testlog

import (
	"fmt"
	"log/slog"
	"reflect"
	"testing"
)

// recordingTB records failures instead of failing the real test, so AssertNoSecrets's failure
// paths can be exercised.
type recordingTB struct {
	testing.TB
	errors []string
	fatals []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func (r *recordingTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func TestCaptureDebug(t *testing.T) {
	logs := CaptureDebug(t)

	slog.Debug("test", "value", "ABCDEF")

	got := leakedSecrets(logs.String(), map[string]string{"hex": "abcdef", "other": "123456"})
	if !reflect.DeepEqual(got, []string{"hex"}) {
		t.Errorf("leakedSecrets = %v, want [hex] (logs: %q)", got, logs.String())
	}

	AssertNoSecrets(t, logs.String(), map[string]string{"other": "123456"})
}

func TestAssertNoSecretsReportsLeak(t *testing.T) {
	var r recordingTB
	AssertNoSecrets(&r, "level=DEBUG msg=x key=abcdef", map[string]string{"session key": "ABCDEF"})

	if !reflect.DeepEqual(r.errors, []string{"session key found in debug logs"}) {
		t.Errorf("errors = %v", r.errors)
	}
}

func TestAssertNoSecretsRequiresCapturedLogs(t *testing.T) {
	var r recordingTB
	AssertNoSecrets(&r, "", map[string]string{"session key": "ABCDEF"})

	if len(r.fatals) != 1 {
		t.Errorf("expected a fatal for empty logs, got %v", r.fatals)
	}
}
