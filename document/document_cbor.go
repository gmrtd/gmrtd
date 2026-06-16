package document

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
)

// rawDoc is an internal CBOR-serialisable snapshot of a document's raw bytes.
type rawDoc struct {
	CardAccess   []byte `cbor:"cardAccess,omitempty"`
	CardSecurity []byte `cbor:"cardSecurity,omitempty"`
	Dir          []byte `cbor:"dir,omitempty"`
	Com          []byte `cbor:"com,omitempty"`
	Sod          []byte `cbor:"sod,omitempty"`
	Dg1          []byte `cbor:"dg1,omitempty"`
	Dg2          []byte `cbor:"dg2,omitempty"`
	Dg7          []byte `cbor:"dg7,omitempty"`
	Dg11         []byte `cbor:"dg11,omitempty"`
	Dg12         []byte `cbor:"dg12,omitempty"`
	Dg13         []byte `cbor:"dg13,omitempty"`
	Dg14         []byte `cbor:"dg14,omitempty"`
	Dg15         []byte `cbor:"dg15,omitempty"`
	Dg16         []byte `cbor:"dg16,omitempty"`
}

const envelopeMagic = "gmrtd-raw-doc"
const envelopeVersion uint = 1

// cborEnvelope is the outer CBOR wrapper that frames a serialised rawDoc.
// The SHA-256 checksum covers the payload bytes exactly, enabling corruption
// detection before the inner document is parsed.
type cborEnvelope struct {
	Magic   string `cbor:"magic"`
	Version uint   `cbor:"version"`
	SHA256  []byte `cbor:"sha256"`
	Payload []byte `cbor:"payload"`
}

// ToCbor returns a CBOR-encoded binary snapshot of the document containing
// only the RawData bytes for each present file, wrapped in a versioned
// envelope with a SHA-256 integrity checksum.
func (doc *Document) ToCbor() ([]byte, error) {
	mf := doc.Mf
	raw := rawDoc{}

	if mf.CardAccess != nil {
		raw.CardAccess = mf.CardAccess.GetRawData()
	}
	if mf.CardSecurity != nil {
		raw.CardSecurity = mf.CardSecurity.GetRawData()
	}
	if mf.Dir != nil {
		raw.Dir = mf.Dir.GetRawData()
	}
	if mf.Lds1.Com != nil {
		raw.Com = mf.Lds1.Com.GetRawData()
	}
	if mf.Lds1.Sod != nil {
		raw.Sod = mf.Lds1.Sod.GetRawData()
	}
	if mf.Lds1.Dg1 != nil {
		raw.Dg1 = mf.Lds1.Dg1.GetRawData()
	}
	if mf.Lds1.Dg2 != nil {
		raw.Dg2 = mf.Lds1.Dg2.GetRawData()
	}
	if mf.Lds1.Dg7 != nil {
		raw.Dg7 = mf.Lds1.Dg7.GetRawData()
	}
	if mf.Lds1.Dg11 != nil {
		raw.Dg11 = mf.Lds1.Dg11.GetRawData()
	}
	if mf.Lds1.Dg12 != nil {
		raw.Dg12 = mf.Lds1.Dg12.GetRawData()
	}
	if mf.Lds1.Dg13 != nil {
		raw.Dg13 = mf.Lds1.Dg13.GetRawData()
	}
	if mf.Lds1.Dg14 != nil {
		raw.Dg14 = mf.Lds1.Dg14.GetRawData()
	}
	if mf.Lds1.Dg15 != nil {
		raw.Dg15 = mf.Lds1.Dg15.GetRawData()
	}
	if mf.Lds1.Dg16 != nil {
		raw.Dg16 = mf.Lds1.Dg16.GetRawData()
	}

	payload, err := cbor.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("[ToCbor] cbor.Marshal(rawDoc) error: %w", err)
	}

	digest := sha256.Sum256(payload)
	env := cborEnvelope{
		Magic:   envelopeMagic,
		Version: envelopeVersion,
		SHA256:  digest[:],
		Payload: payload,
	}

	return cbor.Marshal(env)
}

// NewDocumentFromCbor decodes a CBOR blob produced by ToCbor and reconstructs a
// Document by passing each raw byte slice through its normal constructor.
func NewDocumentFromCbor(data []byte) (*Document, error) {
	var env cborEnvelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] cbor.Unmarshal(envelope) error: %w", err)
	}

	if env.Magic != envelopeMagic {
		return nil, fmt.Errorf("[NewDocumentFromCbor] unrecognised magic %q (want %q)", env.Magic, envelopeMagic)
	}
	if env.Version > envelopeVersion {
		return nil, fmt.Errorf("[NewDocumentFromCbor] unsupported version %d (max supported: %d)", env.Version, envelopeVersion)
	}

	digest := sha256.Sum256(env.Payload)
	if !bytes.Equal(digest[:], env.SHA256) {
		return nil, fmt.Errorf("[NewDocumentFromCbor] SHA-256 checksum mismatch: payload is corrupt")
	}

	var raw rawDoc
	if err := cbor.Unmarshal(env.Payload, &raw); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] cbor.Unmarshal(rawDoc) error: %w", err)
	}

	var doc Document
	var err error

	if doc.Mf.CardAccess, err = NewCardAccess(raw.CardAccess); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewCardAccess error: %w", err)
	}
	if doc.Mf.CardSecurity, err = NewCardSecurity(raw.CardSecurity); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewCardSecurity error: %w", err)
	}
	if doc.Mf.Dir, err = NewEFDIR(raw.Dir); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewEFDIR error: %w", err)
	}
	if doc.Mf.Lds1.Com, err = NewCOM(raw.Com); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewCOM error: %w", err)
	}
	if doc.Mf.Lds1.Sod, err = NewSOD(raw.Sod); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewSOD error: %w", err)
	}
	if doc.Mf.Lds1.Dg1, err = NewDG1(raw.Dg1); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG1 error: %w", err)
	}
	if doc.Mf.Lds1.Dg2, err = NewDG2(raw.Dg2); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG2 error: %w", err)
	}
	if doc.Mf.Lds1.Dg7, err = NewDG7(raw.Dg7); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG7 error: %w", err)
	}
	if doc.Mf.Lds1.Dg11, err = NewDG11(raw.Dg11); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG11 error: %w", err)
	}
	if doc.Mf.Lds1.Dg12, err = NewDG12(raw.Dg12); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG12 error: %w", err)
	}
	if doc.Mf.Lds1.Dg13, err = NewDG13(raw.Dg13); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG13 error: %w", err)
	}
	if doc.Mf.Lds1.Dg14, err = NewDG14(raw.Dg14); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG14 error: %w", err)
	}
	if doc.Mf.Lds1.Dg15, err = NewDG15(raw.Dg15); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG15 error: %w", err)
	}
	if doc.Mf.Lds1.Dg16, err = NewDG16(raw.Dg16); err != nil {
		return nil, fmt.Errorf("[NewDocumentFromCbor] NewDG16 error: %w", err)
	}

	return &doc, nil
}
