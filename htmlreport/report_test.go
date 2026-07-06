package htmlreport

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/tlv"
)

func TestExecuteDocumentTemplateError(t *testing.T) {
	tmpl := template.Must(template.New("not-output").Parse(`hello`))

	out, err := executeDocumentTemplate(tmpl, &templateData{DocumentEx: &document.DocumentEx{}})
	if err == nil {
		t.Fatalf("expected error")
	}
	if out != nil {
		t.Fatalf("expected nil output")
	}
	if !strings.Contains(err.Error(), "ExecuteTemplate") {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestGenerateNilError(t *testing.T) {
	buf, err := Generate(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil documentEx")
	}
	if buf != nil {
		t.Fatal("expected nil buffer")
	}
}

func TestGenerateEmptyDocumentEx(t *testing.T) {
	buf, err := Generate(&document.DocumentEx{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if buf == nil || buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(buf.String(), "GMRTD") {
		t.Error("output does not contain expected title text")
	}
}

func TestGenerateWithSession(t *testing.T) {
	// simple valid DER-encoded certificate stub (wraps a tiny SEQUENCE)
	certDer := []byte{0x30, 0x03, 0x02, 0x01, 0x01}

	docEx := &document.DocumentEx{
		Session: document.Session{
			ChipActivationRsp: &document.ChipActivationRsp{
				Atr: []byte{0x3B, 0x80},
				Ats: []byte{0x60},
			},
			BacResult:        &document.BacResult{Success: true},
			PaceResult:       &document.PaceResult{Success: true},
			PaceCamResult:    &document.PaceCamResult{Success: true},
			ChipAuthResult:   &document.ChipAuthResult{Success: true},
			ActiveAuthResult: &document.ActiveAuthResult{Success: true},
			PassiveAuthResult: &document.PassiveAuthResult{
				Success: true,
				Sod:     document.NewPassiveAuth([][]byte{certDer}),
				CardSec: document.NewPassiveAuth([][]byte{certDer}),
			},
			Summary: &document.DocumentSummary{
				DataTrusted:      true,
				ChipAuthenticity: document.CHIP_AUTH_STATUS_CA,
			},
		},
	}

	buf, err := Generate(docEx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if buf == nil || buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestGenerateWithSessionErrors(t *testing.T) {
	docEx := &document.DocumentEx{
		Session: document.Session{
			BacErr:         fmt.Errorf("bac error"),
			PaceErr:        fmt.Errorf("pace error"),
			ChipAuthErr:    fmt.Errorf("chip auth error"),
			ActiveAuthErr:  fmt.Errorf("active auth error"),
			PassiveAuthErr: fmt.Errorf("passive auth error"),
		},
	}

	buf, err := Generate(docEx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if buf == nil || buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestGenerateWithApduLog(t *testing.T) {
	log := iso7816.NewApduLog()

	entry := iso7816.NewApduLogEntry("SELECT", []byte{0x00, 0xA4, 0x04, 0x0C})
	entry.Finalise([]byte{0x90, 0x00})
	log.Add(entry)

	entryWithChild := iso7816.NewApduLogEntry("READ", []byte{0x00, 0xB0, 0x00, 0x00})
	child := iso7816.NewApduLogEntry("child", []byte{0x01, 0x02})
	child.Finalise([]byte{0x03, 0x04})
	entryWithChild.SetChild(child)
	entryWithChild.Finalise([]byte{0x01, 0x02, 0x90, 0x00})
	log.Add(entryWithChild)

	buf, err := Generate(&document.DocumentEx{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if buf == nil || buf.Len() == 0 {
		t.Fatal("expected non-empty output")
	}
}

func TestTemplateFuncMapGmrtdVersion(t *testing.T) {
	fn := templateFuncMap()["GmrtdVersion"].(func() string)
	if fn() == "" {
		t.Error("GmrtdVersion returned empty string")
	}
}

func TestTemplateFuncMapBytesToHex(t *testing.T) {
	fn := templateFuncMap()["BytesToHex"].(func([]byte) string)
	if got := fn([]byte{0xAB, 0xCD}); got != "ABCD" {
		t.Errorf("BytesToHex: got %q, want %q", got, "ABCD")
	}
	if got := fn(nil); got != "" {
		t.Errorf("BytesToHex(nil): got %q, want %q", got, "")
	}
}

func TestTemplateFuncMapBytesToStr(t *testing.T) {
	fn := templateFuncMap()["BytesToStr"].(func([]byte) string)
	if got := fn([]byte("hello")); got != "hello" {
		t.Errorf("BytesToStr: got %q, want %q", got, "hello")
	}
}

func TestTemplateFuncMapByteLen(t *testing.T) {
	fn := templateFuncMap()["ByteLen"].(func([]byte) int)
	if got := fn([]byte{1, 2, 3}); got != 3 {
		t.Errorf("ByteLen: got %d, want 3", got)
	}
	if got := fn(nil); got != 0 {
		t.Errorf("ByteLen(nil): got %d, want 0", got)
	}
}

func TestTemplateFuncMapTagToHex(t *testing.T) {
	fn := templateFuncMap()["TagToHex"].(func(tlv.TlvTag) string)
	if got := fn(tlv.TlvTag(0x5F1F)); got != "5F1F" {
		t.Errorf("TagToHex: got %q, want %q", got, "5F1F")
	}
}


func TestTemplateFuncMapDecodeTlvBytes(t *testing.T) {
	fn := templateFuncMap()["DecodeTlvBytes"].(func([]byte) []tlv.TlvNode)
	nodes := fn([]byte{0x01, 0x01, 0xFF})
	if len(nodes) == 0 {
		t.Error("DecodeTlvBytes returned no nodes for valid TLV")
	}
}

func TestTemplateFuncMapBytesToBase64(t *testing.T) {
	fn := templateFuncMap()["BytesToBase64"].(func([]byte) string)
	input := []byte("hello")
	got := fn(input)
	want := base64.StdEncoding.EncodeToString(input)
	if got != want {
		t.Errorf("BytesToBase64: got %q, want %q", got, want)
	}
}

func TestTemplateFuncMapOidDesc(t *testing.T) {
	fn := templateFuncMap()["OidDesc"].(func([]byte) string)
	// raw content bytes for OID 2.5.4.3 (CommonName): 0x55 0x04 0x03
	got := fn([]byte{0x55, 0x04, 0x03})
	if got == "" {
		t.Error("OidDesc returned empty string")
	}
	if !strings.Contains(got, "2.5.4.3") {
		t.Errorf("OidDesc: expected OID string in output, got %q", got)
	}
}

func TestTemplateFuncMapIsPrintable(t *testing.T) {
	fn := templateFuncMap()["IsPrintable"].(func([]byte) bool)
	if !fn([]byte("hello")) {
		t.Error("IsPrintable: expected true for printable ASCII bytes")
	}
	if fn([]byte{0x00, 0x01}) {
		t.Error("IsPrintable: expected false for non-printable bytes")
	}
	if fn(nil) {
		t.Error("IsPrintable: expected false for nil")
	}
}

func TestTemplateFuncMapApduTotalDurMs(t *testing.T) {
	fn := templateFuncMap()["ApduTotalDurMs"].(func([]*iso7816.ApduLogEntry) int)
	entries := []*iso7816.ApduLogEntry{
		{DurMs: 10},
		{DurMs: 25},
	}
	if got := fn(entries); got != 35 {
		t.Errorf("ApduTotalDurMs: got %d, want 35", got)
	}
	if got := fn(nil); got != 0 {
		t.Errorf("ApduTotalDurMs(nil): got %d, want 0", got)
	}
}

func TestTemplateFuncMapIndentedJson(t *testing.T) {
	fn := templateFuncMap()["IndentedJson"].(func(any) string)
	got := fn(map[string]int{"a": 1})
	if !strings.Contains(got, `"a"`) {
		t.Errorf("IndentedJson: unexpected output %q", got)
	}
}
