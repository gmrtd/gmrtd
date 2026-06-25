package document

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
)

type rawDocumentEx struct {
	Document         []byte `cbor:"document"`
	ChipAuthEvidence []byte `cbor:"chipAuthEvidence"`
}

const documentExMagic = "gmrtd-verifiable-doc"
const documentExVersion uint = 1

func (docEx *DocumentEx) ToCbor() ([]byte, error) {
	docBytes, err := docEx.Document.ToCbor()
	if err != nil {
		return nil, fmt.Errorf("[DocumentEx.ToCbor] Document.ToCbor error: %w", err)
	}

	caBytes, err := docEx.Session.ChipAuthEvidenceToCbor()
	if err != nil {
		return nil, fmt.Errorf("[DocumentEx.ToCbor] ChipAuthEvidenceToCbor error: %w", err)
	}

	raw := rawDocumentEx{
		Document:         docBytes,
		ChipAuthEvidence: caBytes,
	}

	payload, err := cbor.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("[DocumentEx.ToCbor] cbor.Marshal(rawDocumentEx) error: %w", err)
	}

	digest := sha256.Sum256(payload)
	env := cborEnvelope{
		Magic:   documentExMagic,
		Version: documentExVersion,
		SHA256:  digest[:],
		Payload: payload,
	}

	return cbor.Marshal(env)
}

func UnmarshalVerifiableDoc(data []byte) (*Document, *ChipAuthEvidenceBundle, error) {
	var env cborEnvelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] cbor.Unmarshal(envelope) error: %w", err)
	}

	if env.Magic != documentExMagic {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] unrecognised magic %q (want %q)", env.Magic, documentExMagic)
	}
	if env.Version > documentExVersion {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] unsupported version %d (max supported: %d)", env.Version, documentExVersion)
	}

	digest := sha256.Sum256(env.Payload)
	if !bytes.Equal(digest[:], env.SHA256) {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] SHA-256 checksum mismatch: payload is corrupt")
	}

	var raw rawDocumentEx
	if err := cbor.Unmarshal(env.Payload, &raw); err != nil {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] cbor.Unmarshal(rawDocumentEx) error: %w", err)
	}

	doc, err := NewDocumentFromCbor(raw.Document)
	if err != nil {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] NewDocumentFromCbor error: %w", err)
	}

	caBundle, err := NewChipAuthEvidenceFromCbor(raw.ChipAuthEvidence)
	if err != nil {
		return nil, nil, fmt.Errorf("[UnmarshalVerifiableDoc] NewChipAuthEvidenceFromCbor error: %w", err)
	}

	return doc, caBundle, nil
}
