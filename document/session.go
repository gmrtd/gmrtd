package document

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
)

// Session records the outcome of each step of a document read or offline verification: an
// error and a result for BAC, PACE, Chip Authentication, Active Authentication and
// Passive Authentication, and the result of Document.Verify.
type Session struct {
	ChipActivationRsp *ChipActivationRsp `json:"chipActivationRsp,omitempty"`

	// BAC
	BacErr    error      `json:"bacErr,omitempty"`
	BacResult *BacResult `json:"bacResult,omitempty"`

	// PACE
	PaceErr       error          `json:"paceErr,omitempty"`
	PaceResult    *PaceResult    `json:"paceResult,omitempty"`
	PaceCamResult *PaceCamResult `json:"paceCamResult,omitempty"`

	// Chip Authentication
	ChipAuthErr    error           `json:"chipAuthErr,omitempty"`
	ChipAuthResult *ChipAuthResult `json:"chipAuthResult,omitempty"`

	// Active Authentication
	ActiveAuthErr    error             `json:"activeAuthErr,omitempty"`
	ActiveAuthResult *ActiveAuthResult `json:"activeAuthResult,omitempty"`

	// Document structural/completeness checks (see Document.Verify)
	DocumentVerifyErr error `json:"documentVerifyErr,omitempty"`

	// Passive Authentication
	PassiveAuthErr    error              `json:"passiveAuthErr,omitempty"`
	PassiveAuthResult *PassiveAuthResult `json:"passiveAuthResult,omitempty"`

	// Offline is set when this Session was produced by replaying evidence offline (see
	// verifier.Verify) rather than by a live read; nil for live reads.
	Offline *OfflineVerification `json:"offline,omitempty"`
}

// OfflineVerification records how far chip authentication evidence replayed offline can be
// trusted. It is set by the verifier from its own configuration, never from the evidence file.
//
// CA and PACE-CAM evidence only shows the evidence was not modified after capture: whoever
// captured it knew the terminal's ephemeral private key, so could have produced it without the
// chip. It therefore only counts when the caller vouches that the capturing reader is trusted.
// AA evidence proves the chip signed the nonce, but without a verifier-issued challenge the
// signature may be replayed from an earlier read.
type OfflineVerification struct {
	// TrustedSource is the caller's assertion that the evidence was captured by a trusted reader
	// (e.g. its own kiosk or an attested app), so replayed CA/PACE-CAM/AA evidence is accepted.
	TrustedSource bool `json:"trustedSource"`

	// AAChallengeBound reports that the verifier validated the AA signature over its supplied challenge.
	AAChallengeBound bool `json:"aaChallengeBound"`
}

// ChipAuthProtocolCompleted reports whether a chip authentication protocol (PACE-CAM/CA/AA)
// completed successfully. This reflects protocol outcome only — the public key used is
// chip-supplied and unverified. Do NOT use as an anti-cloning verdict; use
// VerifiedChipAuthStatus() which gates on passive authentication.
func (session Session) ChipAuthProtocolCompleted() bool {
	status := session.ChipAuthProtocolStatus()

	if status == CHIP_AUTH_STATUS_AA ||
		status == CHIP_AUTH_STATUS_CA ||
		status == CHIP_AUTH_STATUS_PACE_CAM {
		return true
	}

	return false
}

// ChipAuthProtocolStatus reports which chip authentication protocol completed successfully
// (AA, PACE-CAM, or CA). This reflects protocol outcome only — the public key used is
// chip-supplied and unverified. Do NOT use as an anti-cloning verdict; use
// VerifiedChipAuthStatus() which gates on passive authentication.
func (session Session) ChipAuthProtocolStatus() (status ChipAuthStatus) {
	// AA
	// note: AA has the strongest backend verification level, so report AA over others (when available)
	if session.ActiveAuthResult != nil && session.ActiveAuthResult.Success {
		return CHIP_AUTH_STATUS_AA
	}

	// PACE-CAM
	if session.PaceCamResult != nil && session.PaceCamResult.Success {
		return CHIP_AUTH_STATUS_PACE_CAM
	}

	// CA
	if session.ChipAuthResult != nil && session.ChipAuthResult.Success {
		return CHIP_AUTH_STATUS_CA
	}

	return CHIP_AUTH_STATUS_NONE
}

// VerifiedChipAuthStatus reports chip authentication status only when the corresponding
// public key is bound to a CSCA-trusted passive authentication chain. Without this binding,
// CA/AA/PACE-CAM only prove the chip holds the private key matching a key it supplied itself,
// which a clone trivially satisfies with its own keypair.
//
// CA/AA: requires PassiveAuthResult.Success (SOD verified via CSCA, DG14/DG15 hashes match).
// PACE-CAM: additionally requires CardSecurity verification (PassiveAuthResult.CardSec != nil).
//
// Offline sessions (Offline != nil) from an untrusted source only count AA bound to a
// verifier-issued challenge; see OfflineVerification.
func (session Session) VerifiedChipAuthStatus() ChipAuthStatus {
	if session.PassiveAuthResult == nil || !session.PassiveAuthResult.Success {
		return CHIP_AUTH_STATUS_NONE
	}

	if session.Offline != nil && !session.Offline.TrustedSource {
		return session.untrustedOfflineChipAuthStatus()
	}

	status := session.ChipAuthProtocolStatus()

	// PACE-CAM key comes from CardSecurity — require it was independently verified
	if status == CHIP_AUTH_STATUS_PACE_CAM && session.PassiveAuthResult.CardSec == nil {
		return CHIP_AUTH_STATUS_NONE
	}

	return status
}

// untrustedOfflineChipAuthStatus only accepts AA bound to a verifier-issued challenge: it is
// the only replayed evidence that the capturing reader could not have produced without the chip.
func (session Session) untrustedOfflineChipAuthStatus() ChipAuthStatus {
	if session.Offline.AAChallengeBound && session.ActiveAuthResult != nil && session.ActiveAuthResult.Success {
		return CHIP_AUTH_STATUS_AA
	}
	return CHIP_AUTH_STATUS_NONE
}

// ChipActivationRsp holds the ATR and ATS returned by the chip when it was activated.
type ChipActivationRsp struct {
	Atr []byte `json:"atr,omitempty"`
	Ats []byte `json:"ats,omitempty"`
}

// BacResult is the outcome of Basic Access Control.
type BacResult struct {
	Success bool `json:"success"`
}

// PaceResult is the outcome of PACE, with the protocol OID and standardised domain
// parameter ID used.
type PaceResult struct {
	Success     bool                  `json:"success"`
	Oid         asn1.ObjectIdentifier `json:"oid"`
	ParameterId int                   `json:"parameterId"`
}

// MarshalJSON encodes the PaceResult with the protocol OID in dotted form.
func (result PaceResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Success     bool   `json:"success"`
		Oid         string `json:"oid"`
		ParameterId int    `json:"parameterId"`
	}{
		Success:     result.Success,
		Oid:         result.Oid.String(),
		ParameterId: result.ParameterId,
	})
}

// PaceCamResult holds the outcome of a PACE-CAM session or an offline evidence
// verification. See PaceCamEvidence for the security properties and limitations of
// offline verification.
type PaceCamResult struct {
	Success  bool             `json:"success"`
	Evidence *PaceCamEvidence `json:"evidence,omitempty"`
}

// MarshalJSON encodes the PaceCamResult and its evidence.
func (result PaceCamResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Success  bool             `json:"success"`
		Evidence *PaceCamEvidence `json:"evidence,omitempty"`
	}{
		Success:  result.Success,
		Evidence: result.Evidence,
	})
}

// PaceCamEvidence holds the cryptographic material captured during a PACE-CAM session
// for offline consistency verification via pace.VerifyEvidence.
//
// The bundle contains the terminal's ephemeral private and public keys (mapping and
// key-agreement phases), the chip's ephemeral public keys, and the encrypted chip
// authentication data (EcadIC). Together these allow the full PACE-CAM key-derivation
// chain to be replayed offline, confirming internal consistency and that the CAM formula
// KA(caIC, pkIC) == ChipMapPub holds for the pkIC in CardSecurity.
//
// Security limitation: the evidence cannot prove a genuine chip was present. The live
// session's security rests on a temporal commitment — the chip sends ChipMapPub before
// TermKaPub exists, so ksEnc is not yet determined when the chip commits. Offline, that
// ordering is lost: a forger can pick any caIC scalar, compute ChipMapPub = caIC·pkIC
// (a forward scalar multiplication requiring no private key), and build consistent
// ChipKaPub and EcadIC without ever holding skCA_IC. An offline-verifiable proof of chip
// key possession would require the chip to produce a non-interactive proof of knowledge
// of skCA_IC (e.g. a Schnorr proof over the session transcript) — PACE-CAM does not
// include this. Active Authentication, where the passport supports it, provides an
// equivalent proof via a conventional signature.
//
// This evidence is best understood as tamper-detection on material captured by a trusted
// terminal. Most single-field modifications break the cryptographic chain. Exception:
// ChipKaPub and EcadIC can be replaced simultaneously by anyone who reads the bundle
// (see pace.VerifyEvidence for details). It must be paired with Passive Authentication
// (binding CardSecurity to a CSCA chain) and trust in the capturing terminal for the
// overall claim to be meaningful.
//
// The terminal ephemeral private keys are safe to include: they are generated fresh for
// each PACE session and carry no value once the session ends.
type PaceCamEvidence struct {
	PaceOid     asn1.ObjectIdentifier `json:"paceOid"`
	ParameterId int                   `json:"parameterId"`
	Nonce       []byte                `json:"nonce"`
	TermMapPri  []byte                `json:"termMapPri"`
	TermMapPub  []byte                `json:"termMapPub"`
	ChipMapPub  []byte                `json:"chipMapPub"`
	TermKaPri   []byte                `json:"termKaPri"`
	TermKaPub   []byte                `json:"termKaPub"`
	ChipKaPub   []byte                `json:"chipKaPub"`
	EcadIC      []byte                `json:"ecadIC"`
}

// MarshalJSON encodes the PaceCamEvidence with the PACE OID in dotted form.
func (evidence PaceCamEvidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PaceOid     string `json:"paceOid"`
		ParameterId int    `json:"parameterId"`
		Nonce       []byte `json:"nonce"`
		TermMapPri  []byte `json:"termMapPri"`
		TermMapPub  []byte `json:"termMapPub"`
		ChipMapPub  []byte `json:"chipMapPub"`
		TermKaPri   []byte `json:"termKaPri"`
		TermKaPub   []byte `json:"termKaPub"`
		ChipKaPub   []byte `json:"chipKaPub"`
		EcadIC      []byte `json:"ecadIC"`
	}{
		PaceOid:     evidence.PaceOid.String(),
		ParameterId: evidence.ParameterId,
		Nonce:       evidence.Nonce,
		TermMapPri:  evidence.TermMapPri,
		TermMapPub:  evidence.TermMapPub,
		ChipMapPub:  evidence.ChipMapPub,
		TermKaPri:   evidence.TermKaPri,
		TermKaPub:   evidence.TermKaPub,
		ChipKaPub:   evidence.ChipKaPub,
		EcadIC:      evidence.EcadIC,
	})
}

// ActiveAuthEvidence holds the challenge nonce and the chip's signature over it from
// the AA protocol. Together with the Document (which contains the chip's public key
// in DG15), this is sufficient for independent cryptographic re-verification.
//
// A successful re-verification only proves the chip holds the private key matching
// the DG15 public key — it must be paired with a positive passive authentication
// result to confirm the key is bound to a CSCA-trusted chain.
//
// The nonce is generated fresh by the terminal for each AA session — it serves as a
// challenge to prove the chip holds the private key matching the DG15 public key.
// Including it enables the verifier to re-check the signature against the public key
// and the original challenge.
type ActiveAuthEvidence struct {
	Algorithm asn1.ObjectIdentifier `json:"algorithm"`
	Nonce     []byte                `json:"nonce"`
	Signature []byte                `json:"signature"`
}

// MarshalJSON encodes the ActiveAuthEvidence with the algorithm OID in dotted form.
func (evidence ActiveAuthEvidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Algorithm string `json:"algorithm"`
		Nonce     []byte `json:"nonce"`
		Signature []byte `json:"signature"`
	}{
		Algorithm: evidence.Algorithm.String(),
		Nonce:     evidence.Nonce,
		Signature: evidence.Signature,
	})
}

// ActiveAuthResult is the outcome of Active Authentication and, if captured, the evidence
// needed to re-verify it offline.
type ActiveAuthResult struct {
	Success  bool                `json:"success"`
	Evidence *ActiveAuthEvidence `json:"evidence,omitempty"`
}

// ChipAuthEvidence holds the ephemeral terminal keypair and the SM-encrypted RAPDU from
// the CA verification step for offline consistency verification via chipauth.VerifyEvidence.
//
// The bundle allows the CA shared secret and session keys to be re-derived offline
// (sharedSecret = TermPri·chipPubKey), then the SM MAC on the captured RAPDU to be
// verified, confirming the evidence is internally consistent.
//
// Security limitation: the evidence cannot prove a genuine chip was present. The CA
// shared secret satisfies sharedSecret = TermPri·chipPubKey = skCA_IC·TermPub, meaning
// it is computable by anyone who knows TermPri and the public chipPubKey — both of which
// are available to the terminal and to anyone who reads the evidence bundle. A forger can
// therefore derive ksMac and construct a MAC-valid SmRapdu without ever holding skCA_IC.
// An offline-verifiable proof of chip key possession would require the chip to produce a
// signature over a session transcript using skCA_IC — CA does not include this.
//
// This evidence is best understood as tamper-detection on material captured by a trusted
// terminal: any post-capture modification breaks the MAC chain. It must be paired with
// Passive Authentication (binding DG14 to a CSCA chain) and trust in the capturing
// terminal for the overall claim to be meaningful.
//
// The terminal ephemeral private key is safe to include: it is generated fresh for each
// CA session and carries no value once the session ends.
type ChipAuthEvidence struct {
	TermPri    []byte `json:"termPri,omitempty"`
	TermPubKey []byte `json:"termPubKey,omitempty"`
	SmRapdu    []byte `json:"smRapdu,omitempty"`
	SmSsc      []byte `json:"smSsc,omitempty"`
}

// ChipAuthResult is the outcome of Chip Authentication and, if captured, the evidence
// needed to re-check it offline.
type ChipAuthResult struct {
	Success  bool              `json:"success"`
	Evidence *ChipAuthEvidence `json:"evidence,omitempty"`
}

// ChipAuthStatus identifies which chip authentication protocol, if any, succeeded. See
// the CHIP_AUTH_STATUS_* constants.
type ChipAuthStatus int

// intentionally use explicit values instead of iota
const (
	CHIP_AUTH_STATUS_NONE     = 0
	CHIP_AUTH_STATUS_PACE_CAM = 1
	CHIP_AUTH_STATUS_CA       = 2
	CHIP_AUTH_STATUS_AA       = 3
)

// String returns a readable name for the status, such as "PACE-CAM", or "n/a" for none.
func (cas ChipAuthStatus) String() string {
	switch cas {
	case CHIP_AUTH_STATUS_NONE:
		return "n/a"
	case CHIP_AUTH_STATUS_PACE_CAM:
		return "PACE-CAM"
	case CHIP_AUTH_STATUS_CA:
		return "Chip Authentication"
	case CHIP_AUTH_STATUS_AA:
		return "Active Authentication"
	}

	return fmt.Sprintf("*UnsupportedValue* (cas:%d)", int(cas))
}

// PassiveAuthResult is the outcome of Passive Authentication. When Success is true, Sod
// and CardSec hold the certificate chains that verified EF.SOD and EF.CardSecurity, and
// CardSec is nil if EF.CardSecurity was not present. When Success is false they may be
// set but empty.
type PassiveAuthResult struct {
	Success bool         `json:"success"`
	Sod     *PassiveAuth `json:"sod,omitempty"`
	CardSec *PassiveAuth `json:"cardSec,omitempty"`
}

// PassiveAuth holds the certificate chain returned when verifying a signed object, one
// DER-encoded certificate per entry.
type PassiveAuth struct {
	CertChain [][]byte `json:"certChain,omitempty"`
}

// NewPassiveAuth returns a PassiveAuth holding certChain.
func NewPassiveAuth(certChain [][]byte) *PassiveAuth {
	return &PassiveAuth{CertChain: certChain}
}
