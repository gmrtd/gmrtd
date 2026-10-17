// Package testlog captures slog output in tests, so they can assert that secrets (access-control
// passwords, private keys, session keys) and the holder's personal data (chip file contents)
// never reach debug logs, which users may share in bug reports.
package testlog

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// CaptureDebug routes the default slog logger to an in-memory buffer at debug level for the rest
// of the test, restoring the previous logger on cleanup. Not safe for use with t.Parallel.
func CaptureDebug(t testing.TB) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return &buf
}

// AssertNoSecrets fails the test if any of the named secrets appears in logs. Matching is
// case-insensitive, so hex-encoded values are found in either case.
func AssertNoSecrets(t testing.TB, logs string, secrets map[string]string) {
	t.Helper()

	if logs == "" {
		t.Fatalf("no debug logs captured; CaptureDebug must be called before the code under test")
	}

	for _, name := range leakedSecrets(logs, secrets) {
		t.Errorf("%s found in debug logs", name)
	}
}

func leakedSecrets(logs string, secrets map[string]string) []string {
	var out []string

	lower := strings.ToLower(logs)
	for name, secret := range secrets {
		if strings.Contains(lower, strings.ToLower(secret)) {
			out = append(out, name)
		}
	}

	slices.Sort(out)

	return out
}
