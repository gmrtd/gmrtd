package document

import (
	"bytes"
	"encoding/asn1"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
)

func TestDocumentExToCbor(t *testing.T) {
	var docEx DocumentEx
	var err error

	docEx.Document.Mf.Lds1.Dg1, err = NewDG1(dg1TestVector)
	if err != nil {
		t.Fatalf("NewDG1 error: %s", err)
	}

	docEx.Session.PaceCamResult = &PaceCamResult{
		Success: true,
		Evidence: &PaceCamEvidence{
			PaceOid:     asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4},
			ParameterId: 13,
			Nonce:       []byte{0x01, 0x02, 0x03},
			TermMapPri:  []byte{0x04, 0x05},
			ChipMapPub:  []byte{0x06, 0x07},
			TermKaPri:   []byte{0x08, 0x09},
			ChipKaPub:   []byte{0x0a, 0x0b},
			EcadIC:      []byte{0x0c, 0x0d},
		},
	}

	cborBytes, err := docEx.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}
	if len(cborBytes) == 0 {
		t.Fatal("ToCbor returned empty bytes")
	}

	var env cborEnvelope
	if err = cbor.Unmarshal(cborBytes, &env); err != nil {
		t.Fatalf("cbor.Unmarshal(envelope) error: %s", err)
	}
	if env.Magic != documentExMagic {
		t.Errorf("magic mismatch: want %q, got %q", documentExMagic, env.Magic)
	}
}

func TestDocumentExRoundTrip(t *testing.T) {
	var src DocumentEx
	var err error

	src.Document.Mf.Lds1.Dg1, err = NewDG1(dg1TestVector)
	if err != nil {
		t.Fatalf("NewDG1 error: %s", err)
	}
	src.Document.Mf.Lds1.Com, err = NewCOM(comTestVector)
	if err != nil {
		t.Fatalf("NewCOM error: %s", err)
	}

	src.Session.ChipAuthResult = &ChipAuthResult{
		Success: true,
		Evidence: &ChipAuthEvidence{
			TermPri:    []byte{0x01, 0x02},
			TermPubKey: []byte{0x03, 0x04},
			SmRapdu:    []byte{0x05, 0x06},
		},
	}

	cborBytes, err := src.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	doc, caBundle, err := UnmarshalVerifiableDoc(cborBytes)
	if err != nil {
		t.Fatalf("UnmarshalVerifiableDoc error: %s", err)
	}

	if doc.Mf.Lds1.Dg1 == nil {
		t.Fatal("expected Dg1 to be non-nil after round-trip")
	}
	if !bytes.Equal(doc.Mf.Lds1.Dg1.RawData, dg1TestVector) {
		t.Errorf("Dg1.RawData mismatch\n  want: %x\n   got: %x", dg1TestVector, doc.Mf.Lds1.Dg1.RawData)
	}

	if doc.Mf.Lds1.Com == nil {
		t.Fatal("expected Com to be non-nil after round-trip")
	}
	if !bytes.Equal(doc.Mf.Lds1.Com.RawData, comTestVector) {
		t.Errorf("Com.RawData mismatch\n  want: %x\n   got: %x", comTestVector, doc.Mf.Lds1.Com.RawData)
	}

	if caBundle.ChipAuth == nil {
		t.Fatal("expected ChipAuth evidence to be non-nil after round-trip")
	}
	if !bytes.Equal(caBundle.ChipAuth.TermPri, []byte{0x01, 0x02}) {
		t.Error("ChipAuth.TermPri mismatch")
	}
	if !bytes.Equal(caBundle.ChipAuth.TermPubKey, []byte{0x03, 0x04}) {
		t.Error("ChipAuth.TermPubKey mismatch")
	}
	if !bytes.Equal(caBundle.ChipAuth.SmRapdu, []byte{0x05, 0x06}) {
		t.Error("ChipAuth.SmRapdu mismatch")
	}
}

func TestDocumentExRoundTripEmpty(t *testing.T) {
	cborBytes, err := (&DocumentEx{}).ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	doc, caBundle, err := UnmarshalVerifiableDoc(cborBytes)
	if err != nil {
		t.Fatalf("UnmarshalVerifiableDoc error: %s", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil Document for empty CBOR")
	}

	if doc.Mf.Lds1.Dg1 != nil {
		t.Error("expected Dg1 to be nil for empty document")
	}
	if caBundle.PaceCam != nil {
		t.Error("expected PaceCam to be nil for empty session")
	}
	if caBundle.ChipAuth != nil {
		t.Error("expected ChipAuth to be nil for empty session")
	}
	if caBundle.ActiveAuth != nil {
		t.Error("expected ActiveAuth to be nil for empty session")
	}
}

func TestDocumentExRoundTripPaceCam(t *testing.T) {
	var src DocumentEx

	src.Session.PaceCamResult = &PaceCamResult{
		Success: true,
		Evidence: &PaceCamEvidence{
			PaceOid:     asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4},
			ParameterId: 13,
			Nonce:       []byte{0x01, 0x02, 0x03},
			TermMapPri:  []byte{0x04, 0x05},
			ChipMapPub:  []byte{0x06, 0x07},
			TermKaPri:   []byte{0x08, 0x09},
			ChipKaPub:   []byte{0x0a, 0x0b},
			EcadIC:      []byte{0x0c, 0x0d},
		},
	}

	cborBytes, err := src.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	_, caBundle, err := UnmarshalVerifiableDoc(cborBytes)
	if err != nil {
		t.Fatalf("UnmarshalVerifiableDoc error: %s", err)
	}

	if caBundle.PaceCam == nil {
		t.Fatal("expected PaceCam evidence to be non-nil")
	}
	if !caBundle.PaceCam.PaceOid.Equal(asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4}) {
		t.Error("PaceCam.PaceOid mismatch")
	}
	if !bytes.Equal(caBundle.PaceCam.Nonce, []byte{0x01, 0x02, 0x03}) {
		t.Error("PaceCam.Nonce mismatch")
	}
	if !bytes.Equal(caBundle.PaceCam.EcadIC, []byte{0x0c, 0x0d}) {
		t.Error("PaceCam.EcadIC mismatch")
	}
	if caBundle.ChipAuth != nil {
		t.Error("expected ChipAuth to be nil")
	}
	if caBundle.ActiveAuth != nil {
		t.Error("expected ActiveAuth to be nil")
	}
}

func TestDocumentExRoundTripAA(t *testing.T) {
	var src DocumentEx

	src.Session.ActiveAuthResult = &ActiveAuthResult{
		Success: true,
		Evidence: &ActiveAuthEvidence{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
			Nonce:     []byte{0xaa, 0xbb},
			Signature: []byte{0xcc, 0xdd},
		},
	}

	cborBytes, err := src.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	_, caBundle, err := UnmarshalVerifiableDoc(cborBytes)
	if err != nil {
		t.Fatalf("UnmarshalVerifiableDoc error: %s", err)
	}

	if caBundle.ActiveAuth == nil {
		t.Fatal("expected ActiveAuth evidence to be non-nil")
	}
	if !caBundle.ActiveAuth.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}) {
		t.Error("ActiveAuth.Algorithm mismatch")
	}
	if !bytes.Equal(caBundle.ActiveAuth.Nonce, []byte{0xaa, 0xbb}) {
		t.Error("ActiveAuth.Nonce mismatch")
	}
	if !bytes.Equal(caBundle.ActiveAuth.Signature, []byte{0xcc, 0xdd}) {
		t.Error("ActiveAuth.Signature mismatch")
	}
	if caBundle.PaceCam != nil {
		t.Error("expected PaceCam to be nil")
	}
	if caBundle.ChipAuth != nil {
		t.Error("expected ChipAuth to be nil")
	}
}

func TestDocumentExFromCborInvalidInput(t *testing.T) {
	_, _, err := UnmarshalVerifiableDoc([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("expected error for invalid CBOR input")
	}
}

func TestDocumentExFromCborBadMagic(t *testing.T) {
	env := cborEnvelope{
		Magic:   "wrong-magic",
		Version: documentExVersion,
		SHA256:  make([]byte, 32),
		Payload: []byte{},
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, _, err = UnmarshalVerifiableDoc(data)
	if err == nil {
		t.Error("expected error for wrong magic")
	}
}

func TestDocumentExFromCborUnsupportedVersion(t *testing.T) {
	payload, _ := cbor.Marshal(rawDocumentEx{})
	env := cborEnvelope{
		Magic:   documentExMagic,
		Version: documentExVersion + 1,
		SHA256:  make([]byte, 32),
		Payload: payload,
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, _, err = UnmarshalVerifiableDoc(data)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestDocumentExFromCborChecksumMismatch(t *testing.T) {
	cborBytes, err := (&DocumentEx{}).ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	var env cborEnvelope
	if err = cbor.Unmarshal(cborBytes, &env); err != nil {
		t.Fatalf("cbor.Unmarshal error: %s", err)
	}
	env.Payload[0] ^= 0xff
	corrupted, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, _, err = UnmarshalVerifiableDoc(corrupted)
	if err == nil {
		t.Error("expected checksum mismatch error for corrupted payload")
	}
}
