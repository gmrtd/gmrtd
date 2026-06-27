package document

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
)

func TestChipAuthEvidenceToCborEmpty(t *testing.T) {
	var session Session

	cborBytes, err := session.ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error on empty session: %s", err)
	}
	if len(cborBytes) == 0 {
		t.Fatal("ChipAuthEvidenceToCbor returned empty bytes")
	}

	result, err := NewChipAuthEvidenceFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewChipAuthEvidenceFromCbor error: %s", err)
	}
	if result.PaceCam != nil || result.ChipAuth != nil || result.ActiveAuth != nil {
		t.Error("expected all evidence to be nil for empty session")
	}
}

func TestChipAuthEvidenceToCborPaceCam(t *testing.T) {
	src := &PaceCamEvidence{
		PaceOid:     asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4},
		ParameterId: 13,
		Nonce:       []byte{0x01, 0x02, 0x03},
		TermMapPri:  []byte{0x04, 0x05},
		TermMapPub:  []byte{0x06, 0x07},
		ChipMapPub:  []byte{0x08, 0x09},
		TermKaPri:   []byte{0x0a, 0x0b},
		TermKaPub:   []byte{0x0c, 0x0d},
		ChipKaPub:   []byte{0x0e, 0x0f},
		EcadIC:      []byte{0x10, 0x11},
	}

	session := Session{
		PaceCamResult: &PaceCamResult{Success: true, Evidence: src},
	}

	cborBytes, err := session.ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error: %s", err)
	}

	result, err := NewChipAuthEvidenceFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewChipAuthEvidenceFromCbor error: %s", err)
	}

	if result.PaceCam == nil {
		t.Fatal("expected PaceCam evidence to be non-nil")
	}
	got := result.PaceCam
	if !got.PaceOid.Equal(src.PaceOid) {
		t.Errorf("PaceOid mismatch: want %s, got %s", src.PaceOid, got.PaceOid)
	}
	if got.ParameterId != src.ParameterId {
		t.Errorf("ParameterId mismatch: want %d, got %d", src.ParameterId, got.ParameterId)
	}
	if !bytes.Equal(got.Nonce, src.Nonce) {
		t.Error("Nonce mismatch")
	}
	if !bytes.Equal(got.TermMapPri, src.TermMapPri) {
		t.Error("TermMapPri mismatch")
	}
	if !bytes.Equal(got.TermMapPub, src.TermMapPub) {
		t.Error("TermMapPub mismatch")
	}
	if !bytes.Equal(got.ChipMapPub, src.ChipMapPub) {
		t.Error("ChipMapPub mismatch")
	}
	if !bytes.Equal(got.TermKaPri, src.TermKaPri) {
		t.Error("TermKaPri mismatch")
	}
	if !bytes.Equal(got.TermKaPub, src.TermKaPub) {
		t.Error("TermKaPub mismatch")
	}
	if !bytes.Equal(got.ChipKaPub, src.ChipKaPub) {
		t.Error("ChipKaPub mismatch")
	}
	if !bytes.Equal(got.EcadIC, src.EcadIC) {
		t.Error("EcadIC mismatch")
	}

	if result.ChipAuth != nil {
		t.Error("expected ChipAuth to be nil")
	}
	if result.ActiveAuth != nil {
		t.Error("expected ActiveAuth to be nil")
	}
}

func TestChipAuthEvidenceToCborCA(t *testing.T) {
	src := &ChipAuthEvidence{
		TermPri:    []byte{0x01, 0x02},
		TermPubKey: []byte{0x03, 0x04},
		SmRapdu:    []byte{0x05, 0x06},
	}

	session := Session{
		ChipAuthResult: &ChipAuthResult{Success: true, Evidence: src},
	}

	cborBytes, err := session.ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error: %s", err)
	}

	result, err := NewChipAuthEvidenceFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewChipAuthEvidenceFromCbor error: %s", err)
	}

	if result.ChipAuth == nil {
		t.Fatal("expected ChipAuth evidence to be non-nil")
	}
	if !bytes.Equal(result.ChipAuth.TermPri, src.TermPri) {
		t.Error("TermPri mismatch")
	}
	if !bytes.Equal(result.ChipAuth.TermPubKey, src.TermPubKey) {
		t.Error("TermPubKey mismatch")
	}
	if !bytes.Equal(result.ChipAuth.SmRapdu, src.SmRapdu) {
		t.Error("SmRapdu mismatch")
	}
}

func TestChipAuthEvidenceToCborAA(t *testing.T) {
	src := &ActiveAuthEvidence{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		Nonce:     []byte{0xaa, 0xbb},
		Signature: []byte{0xcc, 0xdd},
	}

	session := Session{
		ActiveAuthResult: &ActiveAuthResult{Success: true, Evidence: src},
	}

	cborBytes, err := session.ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error: %s", err)
	}

	result, err := NewChipAuthEvidenceFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewChipAuthEvidenceFromCbor error: %s", err)
	}

	if result.ActiveAuth == nil {
		t.Fatal("expected ActiveAuth evidence to be non-nil")
	}
	if !result.ActiveAuth.Algorithm.Equal(src.Algorithm) {
		t.Errorf("Algorithm mismatch: want %s, got %s", src.Algorithm, result.ActiveAuth.Algorithm)
	}
	if !bytes.Equal(result.ActiveAuth.Nonce, src.Nonce) {
		t.Error("Nonce mismatch")
	}
	if !bytes.Equal(result.ActiveAuth.Signature, src.Signature) {
		t.Error("Signature mismatch")
	}
}

func TestChipAuthEvidenceToCborAllThree(t *testing.T) {
	srcPaceCam := &PaceCamEvidence{
		PaceOid:     asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4},
		ParameterId: 13,
		Nonce:       []byte{0x01, 0x02, 0x03},
		TermMapPri:  []byte{0x04, 0x05},
		ChipMapPub:  []byte{0x06, 0x07},
		TermKaPri:   []byte{0x08, 0x09},
		ChipKaPub:   []byte{0x0a, 0x0b},
		EcadIC:      []byte{0x0c, 0x0d},
	}
	srcCA := &ChipAuthEvidence{
		TermPri:    []byte{0x10, 0x11},
		TermPubKey: []byte{0x12, 0x13},
		SmRapdu:    []byte{0x14, 0x15},
	}
	srcAA := &ActiveAuthEvidence{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		Nonce:     []byte{0xaa, 0xbb},
		Signature: []byte{0xcc, 0xdd},
	}

	session := Session{
		PaceCamResult:    &PaceCamResult{Success: true, Evidence: srcPaceCam},
		ChipAuthResult:   &ChipAuthResult{Success: true, Evidence: srcCA},
		ActiveAuthResult: &ActiveAuthResult{Success: true, Evidence: srcAA},
	}

	cborBytes, err := session.ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error: %s", err)
	}

	result, err := NewChipAuthEvidenceFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewChipAuthEvidenceFromCbor error: %s", err)
	}

	if result.PaceCam == nil {
		t.Fatal("expected PaceCam to be non-nil")
	}
	if !result.PaceCam.PaceOid.Equal(srcPaceCam.PaceOid) {
		t.Errorf("PaceCam.PaceOid mismatch: want %s, got %s", srcPaceCam.PaceOid, result.PaceCam.PaceOid)
	}
	if !bytes.Equal(result.PaceCam.Nonce, srcPaceCam.Nonce) {
		t.Error("PaceCam.Nonce mismatch")
	}

	if result.ChipAuth == nil {
		t.Fatal("expected ChipAuth to be non-nil")
	}
	if !bytes.Equal(result.ChipAuth.TermPri, srcCA.TermPri) {
		t.Error("ChipAuth.TermPri mismatch")
	}
	if !bytes.Equal(result.ChipAuth.SmRapdu, srcCA.SmRapdu) {
		t.Error("ChipAuth.SmRapdu mismatch")
	}

	if result.ActiveAuth == nil {
		t.Fatal("expected ActiveAuth to be non-nil")
	}
	if !result.ActiveAuth.Algorithm.Equal(srcAA.Algorithm) {
		t.Errorf("ActiveAuth.Algorithm mismatch: want %s, got %s", srcAA.Algorithm, result.ActiveAuth.Algorithm)
	}
	if !bytes.Equal(result.ActiveAuth.Signature, srcAA.Signature) {
		t.Error("ActiveAuth.Signature mismatch")
	}
}

func TestChipAuthEvidenceToCborResultWithoutEvidence(t *testing.T) {
	session := Session{
		PaceCamResult:    &PaceCamResult{Success: true},
		ChipAuthResult:   &ChipAuthResult{Success: true},
		ActiveAuthResult: &ActiveAuthResult{Success: true},
	}

	cborBytes, err := session.ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error: %s", err)
	}

	result, err := NewChipAuthEvidenceFromCbor(cborBytes)
	if err != nil {
		t.Fatalf("NewChipAuthEvidenceFromCbor error: %s", err)
	}

	if result.PaceCam != nil || result.ChipAuth != nil || result.ActiveAuth != nil {
		t.Error("expected all evidence to be nil when results have no evidence")
	}
}

func TestChipAuthEvidenceFromCborInvalidInput(t *testing.T) {
	_, err := NewChipAuthEvidenceFromCbor([]byte{0xff, 0xff, 0xff})
	if err == nil {
		t.Error("expected error for invalid CBOR input")
	}
}

func TestChipAuthEvidenceFromCborBadMagic(t *testing.T) {
	env := cborEnvelope{
		Magic:   "wrong-magic",
		Version: chipAuthEvidenceVersion,
		SHA256:  make([]byte, 32),
		Payload: []byte{},
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, err = NewChipAuthEvidenceFromCbor(data)
	if err == nil {
		t.Error("expected error for wrong magic")
	}
}

func TestChipAuthEvidenceFromCborObsoleteVersion(t *testing.T) {
	payload, _ := cbor.Marshal(cborChipAuthBundle{})
	digest := sha256.Sum256(payload)
	env := cborEnvelope{
		Magic:   chipAuthEvidenceMagic,
		Version: chipAuthEvidenceMinVersion - 1,
		SHA256:  digest[:],
		Payload: payload,
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, err = NewChipAuthEvidenceFromCbor(data)
	if err == nil {
		t.Error("expected error for obsolete bundle version")
	}
}

func TestChipAuthEvidenceFromCborUnsupportedVersion(t *testing.T) {
	payload, _ := cbor.Marshal(cborChipAuthBundle{})
	env := cborEnvelope{
		Magic:   chipAuthEvidenceMagic,
		Version: chipAuthEvidenceVersion + 1,
		SHA256:  make([]byte, 32),
		Payload: payload,
	}
	data, err := cbor.Marshal(env)
	if err != nil {
		t.Fatalf("cbor.Marshal error: %s", err)
	}

	_, err = NewChipAuthEvidenceFromCbor(data)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestChipAuthEvidenceFromCborChecksumMismatch(t *testing.T) {
	cborBytes, err := (&Session{}).ChipAuthEvidenceToCbor()
	if err != nil {
		t.Fatalf("ChipAuthEvidenceToCbor error: %s", err)
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

	_, err = NewChipAuthEvidenceFromCbor(corrupted)
	if err == nil {
		t.Error("expected checksum mismatch error for corrupted payload")
	}
}
