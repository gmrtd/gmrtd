package document

import (
	"bytes"
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
