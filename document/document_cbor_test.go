package document

import (
	"bytes"
	"crypto/sha256"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/gmrtd/gmrtd/utils"
)

// dg1TestVector is a valid DG1 (MRZ) used across CBOR tests.
var dg1TestVector = utils.HexToBytes("614B5F1F48493C55544F4552494B53534F4E3C3C414E4E413C4D415249413C3C3C3C3C3C3C3C3C3C3C4432333134353839303755544F3734303831323246313230343135393C3C3C3C3C3C3C36")

// comTestVector is a valid EF.COM used across CBOR tests (from 9303-p10).
var comTestVector = utils.HexToBytes("60145F0104303130365F36063034303030305C026175")

func TestToCbor(t *testing.T) {
	dg1Bytes := dg1TestVector

	var doc Document
	var err error

	doc.Mf.Lds1.Dg1, err = NewDG1(dg1Bytes)
	if err != nil {
		t.Fatalf("NewDG1 error: %s", err)
	}

	cborBytes, err := doc.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}
	if len(cborBytes) == 0 {
		t.Fatal("ToCbor returned empty bytes")
	}

	// round-trip: decode the envelope, then the inner rawDoc, and verify DG1 bytes are preserved
	var env cborEnvelope
	if err = cbor.Unmarshal(cborBytes, &env); err != nil {
		t.Fatalf("cbor.Unmarshal(envelope) error: %s", err)
	}
	var decoded rawDoc
	if err = cbor.Unmarshal(env.Payload, &decoded); err != nil {
		t.Fatalf("cbor.Unmarshal(rawDoc) error: %s", err)
	}

	if !bytes.Equal(decoded.Dg1, dg1Bytes) {
		t.Errorf("decoded Dg1 mismatch\n  want: %x\n   got: %x", dg1Bytes, decoded.Dg1)
	}

	// absent fields should be nil (omitempty)
	if decoded.CardAccess != nil {
		t.Errorf("expected CardAccess to be nil when absent")
	}
	if decoded.Dg2 != nil {
		t.Errorf("expected Dg2 to be nil when absent")
	}
}

func TestToCborEmpty(t *testing.T) {
	var doc Document

	cborBytes, err := doc.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error on empty document: %s", err)
	}
	if len(cborBytes) == 0 {
		t.Fatal("ToCbor returned empty bytes for empty document")
	}

	var env cborEnvelope
	if err = cbor.Unmarshal(cborBytes, &env); err != nil {
		t.Fatalf("cbor.Unmarshal(envelope) error: %s", err)
	}
	var decoded rawDoc
	if err = cbor.Unmarshal(env.Payload, &decoded); err != nil {
		t.Fatalf("cbor.Unmarshal(rawDoc) error: %s", err)
	}

	// all fields should be nil for an empty document
	if decoded.Dg1 != nil || decoded.Com != nil || decoded.Sod != nil {
		t.Errorf("expected all fields to be nil for empty document")
	}
}

func TestNewDocumentFromCbor(t *testing.T) {
	// Build a source document with two populated files.
	var src Document
	var err error

	src.Mf.Lds1.Dg1, err = NewDG1(dg1TestVector)
	if err != nil {
		t.Fatalf("NewDG1 error: %s", err)
	}
	src.Mf.Lds1.Com, err = NewCOM(comTestVector)
	if err != nil {
		t.Fatalf("NewCOM error: %s", err)
	}

	// Serialise.
	cborBytes, err := src.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	// Deserialise.
	got, err := NewDocumentFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewDocumentFromCbor error: %s", err)
	}

	// DG1 must be present and RawData must round-trip exactly.
	if got.Mf.Lds1.Dg1 == nil {
		t.Fatal("expected Dg1 to be non-nil after round-trip")
	}
	if !bytes.Equal(got.Mf.Lds1.Dg1.RawData, dg1TestVector) {
		t.Errorf("Dg1.RawData mismatch\n  want: %x\n   got: %x", dg1TestVector, got.Mf.Lds1.Dg1.RawData)
	}

	// COM must be present and RawData must round-trip exactly.
	if got.Mf.Lds1.Com == nil {
		t.Fatal("expected Com to be non-nil after round-trip")
	}
	if !bytes.Equal(got.Mf.Lds1.Com.RawData, comTestVector) {
		t.Errorf("Com.RawData mismatch\n  want: %x\n   got: %x", comTestVector, got.Mf.Lds1.Com.RawData)
	}

	// Absent fields must remain nil.
	if got.Mf.CardAccess != nil {
		t.Errorf("expected CardAccess to be nil when absent")
	}
	if got.Mf.Lds1.Dg2 != nil {
		t.Errorf("expected Dg2 to be nil when absent")
	}
}

func TestNewDocumentFromCborEmpty(t *testing.T) {
	cborBytes, err := (&Document{}).ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	got, err := NewDocumentFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewDocumentFromCbor error on empty document: %s", err)
	}
	if got == nil {
		t.Fatal("expected non-nil Document for empty CBOR")
	}

	// All fields must be nil.
	if got.Mf.CardAccess != nil || got.Mf.Lds1.Dg1 != nil || got.Mf.Lds1.Sod != nil {
		t.Errorf("expected all fields nil for empty document")
	}
}

func TestNewDocumentFromCborInvalidInput(t *testing.T) {
	_, err := NewDocumentFromCbor([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("expected error for invalid CBOR input")
	}
}

func TestNewDocumentFromCborBadMagic(t *testing.T) {
	env := cborEnvelope{
		Magic:   "wrong-magic",
		Version: envelopeVersion,
		SHA256:  make([]byte, 32),
		Payload: []byte{},
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, err = NewDocumentFromCbor(data)
	if err == nil {
		t.Error("expected error for wrong magic")
	}
}

func TestNewDocumentFromCborUnsupportedVersion(t *testing.T) {
	payload, _ := cbor.Marshal(rawDoc{})
	digest := [32]byte{}
	copy(digest[:], payload) // deliberately wrong — version check should fire first
	env := cborEnvelope{
		Magic:   envelopeMagic,
		Version: envelopeVersion + 1,
		SHA256:  digest[:],
		Payload: payload,
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, err = NewDocumentFromCbor(data)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestNewDocumentFromCborChecksumMismatch(t *testing.T) {
	cborBytes, err := (&Document{}).ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	// Decode the envelope, corrupt a byte in the payload, re-encode.
	var env cborEnvelope
	if err = cbor.Unmarshal(cborBytes, &env); err != nil {
		t.Fatalf("cbor.Unmarshal error: %s", err)
	}
	env.Payload[0] ^= 0xff
	corrupted, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, err = NewDocumentFromCbor(corrupted)
	if err == nil {
		t.Error("expected checksum mismatch error for corrupted payload")
	}
}

// buildCborFromRawDoc marshals raw into a complete, checksum-valid CBOR blob that
// NewDocumentFromCbor can decode.
func buildCborFromRawDoc(t *testing.T, raw rawDoc) []byte {
	t.Helper()
	payload, err := cbor.Marshal(raw)
	if err != nil {
		t.Fatalf("cbor.Marshal(rawDoc): %s", err)
	}
	digest := sha256.Sum256(payload)
	env := cborEnvelope{
		Magic:   envelopeMagic,
		Version: envelopeVersion,
		SHA256:  digest[:],
		Payload: payload,
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal(envelope): %s", err)
	}
	return data
}

// TestToCborAllFields exercises every data-file branch in ToCbor by populating
// all fourteen optional fields directly (bypassing constructors, which are
// irrelevant to the serialisation path).
func TestToCborAllFields(t *testing.T) {
	placeholder := []byte{0x01, 0x02, 0x03}

	var doc Document
	doc.Mf.CardAccess = &CardAccess{RawData: placeholder}
	doc.Mf.CardSecurity = &CardSecurity{RawData: placeholder}
	doc.Mf.Dir = &EFDIR{RawData: placeholder}
	doc.Mf.Lds1.Com = &COM{RawData: placeholder}
	doc.Mf.Lds1.Sod = &SOD{RawData: placeholder}
	doc.Mf.Lds1.Dg1 = &DG1{RawData: placeholder}
	doc.Mf.Lds1.Dg2 = &DG2{RawData: placeholder}
	doc.Mf.Lds1.Dg7 = &DG7{RawData: placeholder}
	doc.Mf.Lds1.Dg11 = &DG11{RawData: placeholder}
	doc.Mf.Lds1.Dg12 = &DG12{RawData: placeholder}
	doc.Mf.Lds1.Dg13 = &DG13{RawData: placeholder}
	doc.Mf.Lds1.Dg14 = &DG14{RawData: placeholder}
	doc.Mf.Lds1.Dg15 = &DG15{RawData: placeholder}
	doc.Mf.Lds1.Dg16 = &DG16{RawData: placeholder}

	cborBytes, err := doc.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	var env cborEnvelope
	if err = cbor.Unmarshal(cborBytes, &env); err != nil {
		t.Fatalf("cbor.Unmarshal(envelope): %s", err)
	}
	var decoded rawDoc
	if err = cbor.Unmarshal(env.Payload, &decoded); err != nil {
		t.Fatalf("cbor.Unmarshal(rawDoc): %s", err)
	}

	checks := []struct {
		name string
		got  []byte
	}{
		{"CardAccess", decoded.CardAccess},
		{"CardSecurity", decoded.CardSecurity},
		{"Dir", decoded.Dir},
		{"Com", decoded.Com},
		{"Sod", decoded.Sod},
		{"Dg1", decoded.Dg1},
		{"Dg2", decoded.Dg2},
		{"Dg7", decoded.Dg7},
		{"Dg11", decoded.Dg11},
		{"Dg12", decoded.Dg12},
		{"Dg13", decoded.Dg13},
		{"Dg14", decoded.Dg14},
		{"Dg15", decoded.Dg15},
		{"Dg16", decoded.Dg16},
	}
	for _, c := range checks {
		if !bytes.Equal(c.got, placeholder) {
			t.Errorf("%s: want %x, got %x", c.name, placeholder, c.got)
		}
	}
}

// TestNewDocumentFromCborBadRawDoc covers the cbor.Unmarshal(rawDoc) error path:
// the outer envelope is valid and its checksum matches, but the payload bytes are
// a CBOR integer rather than a CBOR map, so decoding into rawDoc must fail.
func TestNewDocumentFromCborBadRawDoc(t *testing.T) {
	payload := []byte{0x01} // CBOR integer 1, not a map
	digest := sha256.Sum256(payload)
	env := cborEnvelope{
		Magic:   envelopeMagic,
		Version: envelopeVersion,
		SHA256:  digest[:],
		Payload: payload,
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal: %s", err)
	}

	_, err = NewDocumentFromCbor(data)
	if err == nil {
		t.Error("expected error when payload is not a CBOR map")
	}
}

// TestNewDocumentFromCborConstructorErrors verifies that NewDocumentFromCbor
// returns an error when any individual data-file field contains invalid bytes
// that cause its New* constructor to fail.
func TestNewDocumentFromCborConstructorErrors(t *testing.T) {
	badTlv := utils.HexToBytes("02101234") // valid length prefix but too few bytes
	badAsn := utils.HexToBytes("0608")     // truncated ASN.1 (rejects in CardAccess/CardSecurity)
	badTag := utils.HexToBytes("01021234") // valid TLV but wrong root tag

	testCases := []struct {
		name string
		raw  rawDoc
	}{
		{"CardAccess", rawDoc{CardAccess: badAsn}},
		{"CardSecurity", rawDoc{CardSecurity: badAsn}},
		{"Dir", rawDoc{Dir: badTlv}},
		{"Com", rawDoc{Com: badTlv}},
		{"Sod", rawDoc{Sod: badTag}},
		{"Dg1", rawDoc{Dg1: badTlv}},
		{"Dg2", rawDoc{Dg2: badTlv}},
		{"Dg7", rawDoc{Dg7: badTlv}},
		{"Dg11", rawDoc{Dg11: badTlv}},
		{"Dg12", rawDoc{Dg12: badTlv}},
		{"Dg13", rawDoc{Dg13: badTag}},
		{"Dg14", rawDoc{Dg14: badTlv}},
		{"Dg15", rawDoc{Dg15: badTlv}},
		{"Dg16", rawDoc{Dg16: badTlv}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildCborFromRawDoc(t, tc.raw)
			_, err := NewDocumentFromCbor(data)
			if err == nil {
				t.Errorf("expected error for invalid %s bytes", tc.name)
			}
		})
	}
}
