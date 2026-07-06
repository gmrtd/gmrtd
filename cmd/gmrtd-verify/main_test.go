package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
)

func TestCmdParamsSuccess(t *testing.T) {
	tests := []struct {
		name              string
		args              []string
		wantFile          string
		wantDebug         bool
		wantChallengeHex  string
	}{
		{
			name:      "file only",
			args:      []string{"-file", "document.gmrtd"},
			wantFile:  "document.gmrtd",
			wantDebug: false,
		},
		{
			name:      "file with debug",
			args:      []string{"-file", "document.gmrtd", "-debug"},
			wantFile:  "document.gmrtd",
			wantDebug: true,
		},
		{
			name:             "file with challenge",
			args:             []string{"-file", "document.gmrtd", "-challenge", "0102030405060708"},
			wantFile:         "document.gmrtd",
			wantDebug:        false,
			wantChallengeHex: "0102030405060708",
		},
		{
			name:             "file debug and challenge",
			args:             []string{"-file", "document.gmrtd", "-debug", "-challenge", "aabbccddeeff0011"},
			wantFile:         "document.gmrtd",
			wantDebug:        true,
			wantChallengeHex: "aabbccddeeff0011",
		},
		{
			name:      "stdin",
			args:      []string{"-file", "-"},
			wantFile:  "-",
			wantDebug: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filePath, debug, challenge, err := cmdParams(tc.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if filePath != tc.wantFile {
				t.Fatalf("filePath = %q, want %q", filePath, tc.wantFile)
			}
			if debug != tc.wantDebug {
				t.Fatalf("debug = %v, want %v", debug, tc.wantDebug)
			}
			if tc.wantChallengeHex == "" {
				if challenge != nil {
					t.Fatalf("challenge = %x, want nil", challenge)
				}
			} else {
				wantHex := strings.ToLower(tc.wantChallengeHex)
				gotHex := strings.ToLower(fmt.Sprintf("%x", challenge))
				if gotHex != wantHex {
					t.Fatalf("challenge = %s, want %s", gotHex, wantHex)
				}
			}
		})
	}
}

func TestCmdParamsError(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		errContains string
	}{
		{
			name:        "missing file flag",
			args:        []string{},
			errContains: "-file is required",
		},
		{
			name:        "unknown flag",
			args:        []string{"-unknown"},
			errContains: "flag provided but not defined",
		},
		{
			name:        "challenge not valid hex",
			args:        []string{"-file", "document.gmrtd", "-challenge", "zzzzzzzzzzzzzzzz"},
			errContains: "invalid -challenge",
		},
		{
			name:        "challenge too short",
			args:        []string{"-file", "document.gmrtd", "-challenge", "010203"},
			errContains: "must be exactly 8 bytes",
		},
		{
			name:        "challenge too long",
			args:        []string{"-file", "document.gmrtd", "-challenge", "010203040506070809"},
			errContains: "must be exactly 8 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filePath, debug, challenge, err := cmdParams(tc.args)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got %q", tc.errContains, err.Error())
			}
			if filePath != "" {
				t.Fatalf("filePath = %q, want empty on error", filePath)
			}
			if debug != false {
				t.Fatalf("debug = %v, want false on error", debug)
			}
			if challenge != nil {
				t.Fatalf("challenge = %x, want nil on error", challenge)
			}
		})
	}
}

func TestCscaMasterList(t *testing.T) {
	certPool, err := cscaMasterList()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if certPool == nil {
		t.Fatalf("certPool expected")
	}

	const expCertCnt = 500
	if len(certPool.All()) < expCertCnt {
		t.Errorf("expected at least %d certs, got %d", expCertCnt, len(certPool.All()))
	}
}

func makeDeps(overrides func(*appDeps)) appDeps {
	deps := appDeps{
		cscaMasterList: func() (cms.CertPool, error) { return &cms.GenericCertPool{}, nil },
		readFile:       func(string) ([]byte, error) { return []byte("fake"), nil },
		verify: func(cms.CertPool, []byte, []byte) (*document.DocumentEx, error) {
			return &document.DocumentEx{}, nil
		},
		generateDocument: func(*document.DocumentEx, *iso7816.ApduLog) (*bytes.Buffer, error) {
			return bytes.NewBufferString("html"), nil
		},
		openBrowser: func(io.Reader) error { return nil },
	}
	if overrides != nil {
		overrides(&deps)
	}
	return deps
}

func TestRunWithDepsSuccess(t *testing.T) {
	err := runWithDeps([]string{"-file", "document.gmrtd"}, makeDeps(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWithDepsSuccessWithChallenge(t *testing.T) {
	var gotChallenge []byte
	deps := makeDeps(func(d *appDeps) {
		d.verify = func(_ cms.CertPool, challenge []byte, _ []byte) (*document.DocumentEx, error) {
			gotChallenge = challenge
			return &document.DocumentEx{}, nil
		}
	})

	err := runWithDeps([]string{"-file", "document.gmrtd", "-challenge", "0102030405060708"}, deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantChallenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(gotChallenge, wantChallenge) {
		t.Fatalf("challenge = %x, want %x", gotChallenge, wantChallenge)
	}
}

func TestRunWithDepsCmdParamsError(t *testing.T) {
	err := runWithDeps([]string{}, makeDeps(nil))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "-file is required") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestRunWithDepsCscaMasterListError(t *testing.T) {
	wantErr := errors.New("csca boom")

	err := runWithDeps([]string{"-file", "document.gmrtd"}, makeDeps(func(d *appDeps) {
		d.cscaMasterList = func() (cms.CertPool, error) { return nil, wantErr }
	}))

	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestRunWithDepsReadFileError(t *testing.T) {
	wantErr := errors.New("read file boom")

	err := runWithDeps([]string{"-file", "document.gmrtd"}, makeDeps(func(d *appDeps) {
		d.readFile = func(string) ([]byte, error) { return nil, wantErr }
	}))

	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestRunWithDepsVerifyError(t *testing.T) {
	wantErr := errors.New("verify boom")

	err := runWithDeps([]string{"-file", "document.gmrtd"}, makeDeps(func(d *appDeps) {
		d.verify = func(cms.CertPool, []byte, []byte) (*document.DocumentEx, error) {
			return nil, wantErr
		}
	}))

	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestRunWithDepsGenerateDocumentError(t *testing.T) {
	wantErr := errors.New("generate boom")

	err := runWithDeps([]string{"-file", "document.gmrtd"}, makeDeps(func(d *appDeps) {
		d.generateDocument = func(*document.DocumentEx, *iso7816.ApduLog) (*bytes.Buffer, error) {
			return nil, wantErr
		}
	}))

	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestRunWithDepsOpenBrowserError(t *testing.T) {
	wantErr := errors.New("browser boom")

	err := runWithDeps([]string{"-file", "document.gmrtd"}, makeDeps(func(d *appDeps) {
		d.openBrowser = func(io.Reader) error { return wantErr }
	}))

	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestRunWithDepsSuccessWithDebug(t *testing.T) {
	err := runWithDeps([]string{"-file", "document.gmrtd", "-debug"}, makeDeps(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadCborFile(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		f, err := os.CreateTemp("", "*.cbor")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		f.Write([]byte("testdata"))
		f.Close()

		got, err := readCborFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "testdata" {
			t.Fatalf("got %q, want %q", got, "testdata")
		}
	})

	t.Run("stdin", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		orig := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = orig }()
		w.Write([]byte("stdin content"))
		w.Close()

		got, err := readCborFile("-")
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "stdin content" {
			t.Fatalf("got %q, want %q", got, "stdin content")
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := readCborFile("/nonexistent/path/missing.cbor")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestVerifyDocument(t *testing.T) {
	pool := &cms.GenericCertPool{}

	t.Run("invalid cbor no challenge", func(t *testing.T) {
		_, err := verifyDocument(pool, nil, []byte("not valid cbor"))
		if err == nil {
			t.Fatal("expected error for invalid CBOR data")
		}
	})

	t.Run("invalid cbor with challenge", func(t *testing.T) {
		challenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		_, err := verifyDocument(pool, challenge, []byte("not valid cbor"))
		if err == nil {
			t.Fatal("expected error for invalid CBOR data with challenge")
		}
	})
}

func TestDefaultAppDeps(t *testing.T) {
	deps := defaultAppDeps()
	if deps.cscaMasterList == nil {
		t.Error("cscaMasterList is nil")
	}
	if deps.readFile == nil {
		t.Error("readFile is nil")
	}
	if deps.verify == nil {
		t.Error("verify is nil")
	}
	if deps.generateDocument == nil {
		t.Error("generateDocument is nil")
	}
	if deps.openBrowser == nil {
		t.Error("openBrowser is nil")
	}
}

func TestRunMissingFile(t *testing.T) {
	err := run([]string{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "-file is required") {
		t.Fatalf("unexpected error: %s", err)
	}
}
