package document

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
)

type cborPaceCamEvidence struct {
	PaceOid     []int  `cbor:"paceOid"`
	ParameterId int    `cbor:"parameterId"`
	Nonce       []byte `cbor:"nonce"`
	TermMapPri  []byte `cbor:"termMapPri"`
	ChipMapPub  []byte `cbor:"chipMapPub"`
	TermKaPri   []byte `cbor:"termKaPri"`
	ChipKaPub   []byte `cbor:"chipKaPub"`
	EcadIC      []byte `cbor:"ecadIC"`
}

type cborCAEvidence struct {
	TermPri    []byte `cbor:"termPri,omitempty"`
	TermPubKey []byte `cbor:"termPubKey,omitempty"`
	SmRapdu    []byte `cbor:"smRapdu,omitempty"`
}

type cborAAEvidence struct {
	Algorithm []int  `cbor:"algorithm"`
	Nonce     []byte `cbor:"nonce"`
	Signature []byte `cbor:"signature"`
}

type cborChipAuthBundle struct {
	PaceCam    *cborPaceCamEvidence `cbor:"paceCam,omitempty"`
	ChipAuth   *cborCAEvidence      `cbor:"chipAuth,omitempty"`
	ActiveAuth *cborAAEvidence      `cbor:"activeAuth,omitempty"`
}

const chipAuthEvidenceMagic = "gmrtd-chip-auth-evidence"
const chipAuthEvidenceVersion uint = 1

type ChipAuthEvidenceBundle struct {
	PaceCam    *PaceCamEvidence
	ChipAuth   *ChipAuthEvidence
	ActiveAuth *ActiveAuthEvidence
}

func (session *Session) ChipAuthEvidenceToCbor() ([]byte, error) {
	var bundle cborChipAuthBundle

	if session.PaceCamResult != nil && session.PaceCamResult.Evidence != nil {
		e := session.PaceCamResult.Evidence
		bundle.PaceCam = &cborPaceCamEvidence{
			PaceOid:     []int(e.PaceOid),
			ParameterId: e.ParameterId,
			Nonce:       e.Nonce,
			TermMapPri:  e.TermMapPri,
			ChipMapPub:  e.ChipMapPub,
			TermKaPri:   e.TermKaPri,
			ChipKaPub:   e.ChipKaPub,
			EcadIC:      e.EcadIC,
		}
	}

	if session.ChipAuthResult != nil && session.ChipAuthResult.Evidence != nil {
		e := session.ChipAuthResult.Evidence
		bundle.ChipAuth = &cborCAEvidence{
			TermPri:    e.TermPri,
			TermPubKey: e.TermPubKey,
			SmRapdu:    e.SmRapdu,
		}
	}

	if session.ActiveAuthResult != nil && session.ActiveAuthResult.Evidence != nil {
		e := session.ActiveAuthResult.Evidence
		bundle.ActiveAuth = &cborAAEvidence{
			Algorithm: []int(e.Algorithm),
			Nonce:     e.Nonce,
			Signature: e.Signature,
		}
	}

	payload, err := cbor.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("[ChipAuthEvidenceToCbor] cbor.Marshal error: %w", err)
	}

	digest := sha256.Sum256(payload)
	env := cborEnvelope{
		Magic:   chipAuthEvidenceMagic,
		Version: chipAuthEvidenceVersion,
		SHA256:  digest[:],
		Payload: payload,
	}

	return cbor.Marshal(env)
}

func NewChipAuthEvidenceFromCbor(data []byte) (*ChipAuthEvidenceBundle, error) {
	var env cborEnvelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("[NewChipAuthEvidenceFromCbor] cbor.Unmarshal(envelope) error: %w", err)
	}

	if env.Magic != chipAuthEvidenceMagic {
		return nil, fmt.Errorf("[NewChipAuthEvidenceFromCbor] unrecognised magic %q (want %q)", env.Magic, chipAuthEvidenceMagic)
	}
	if env.Version > chipAuthEvidenceVersion {
		return nil, fmt.Errorf("[NewChipAuthEvidenceFromCbor] unsupported version %d (max supported: %d)", env.Version, chipAuthEvidenceVersion)
	}

	digest := sha256.Sum256(env.Payload)
	if !bytes.Equal(digest[:], env.SHA256) {
		return nil, fmt.Errorf("[NewChipAuthEvidenceFromCbor] SHA-256 checksum mismatch: payload is corrupt")
	}

	var bundle cborChipAuthBundle
	if err := cbor.Unmarshal(env.Payload, &bundle); err != nil {
		return nil, fmt.Errorf("[NewChipAuthEvidenceFromCbor] cbor.Unmarshal(bundle) error: %w", err)
	}

	var result ChipAuthEvidenceBundle

	if bundle.PaceCam != nil {
		result.PaceCam = &PaceCamEvidence{
			PaceOid:     asn1.ObjectIdentifier(bundle.PaceCam.PaceOid),
			ParameterId: bundle.PaceCam.ParameterId,
			Nonce:       bundle.PaceCam.Nonce,
			TermMapPri:  bundle.PaceCam.TermMapPri,
			ChipMapPub:  bundle.PaceCam.ChipMapPub,
			TermKaPri:   bundle.PaceCam.TermKaPri,
			ChipKaPub:   bundle.PaceCam.ChipKaPub,
			EcadIC:      bundle.PaceCam.EcadIC,
		}
	}

	if bundle.ChipAuth != nil {
		result.ChipAuth = &ChipAuthEvidence{
			TermPri:    bundle.ChipAuth.TermPri,
			TermPubKey: bundle.ChipAuth.TermPubKey,
			SmRapdu:    bundle.ChipAuth.SmRapdu,
		}
	}

	if bundle.ActiveAuth != nil {
		result.ActiveAuth = &ActiveAuthEvidence{
			Algorithm: asn1.ObjectIdentifier(bundle.ActiveAuth.Algorithm),
			Nonce:     bundle.ActiveAuth.Nonce,
			Signature: bundle.ActiveAuth.Signature,
		}
	}

	return &result, nil
}
