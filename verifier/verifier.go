// Package verifier provides offline verification of machine-readable travel documents (MRTDs)
// by replaying serialised chip authentication evidence and performing passive authentication
// against a CSCA certificate pool.
//
// Replayed evidence cannot prove a chip was present unless the reader that captured it is
// trusted: CA and PACE-CAM evidence can be produced by anyone holding the terminal's ephemeral
// private key, and AA evidence can be replayed from an earlier read. By default the verifier
// treats the source as untrusted, so DocumentEx.Summary().ChipAuthenticity only reports AA bound
// to a challenge supplied via Verifier.WithAAChallenge. Callers whose evidence comes from a
// reader they control can opt in with Verifier.WithTrustedSource.
package verifier

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/gmrtd/gmrtd/activeauth"
	"github.com/gmrtd/gmrtd/chipauth"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/pace"
	"github.com/gmrtd/gmrtd/passiveauth"
)

// Verifier is not safe for concurrent use: it is a single-use, single-goroutine
// object for verifying one piece of evidence. mu guards aaChallenge (set via
// WithAAChallenge) and serialises Verify, so a Verifier that is accidentally
// shared and called from multiple goroutines fails safe (calls queue up)
// rather than corrupting the Go heap.
type Verifier struct {
	mu sync.Mutex

	cscaCertPool  cms.CertPool
	aaChallenge   []byte
	trustedSource bool
}

func NewVerifier(cscaCertPool cms.CertPool) *Verifier {
	return &Verifier{cscaCertPool: cscaCertPool}
}

// WithAAChallenge sets a caller-supplied 8-byte challenge to bind against the
// AA evidence nonce. Security-conscious callers should always supply their own
// challenge rather than relying on the internally generated random value — this
// is what closes the relay-attack window. When set and AA evidence is present,
// Verify returns a hard error if the evidence nonce does not match the supplied
// challenge, or if the AA signature itself fails to verify.
func (v *Verifier) WithAAChallenge(challenge []byte) (*Verifier, error) {
	if len(challenge) != 8 {
		return nil, fmt.Errorf("[WithAAChallenge] challenge must be exactly 8 bytes, got %d", len(challenge))
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.aaChallenge = bytes.Clone(challenge)
	return v, nil
}

// WithTrustedSource declares that the evidence was captured by a trusted reader (e.g. the
// caller's own kiosk, or an app whose integrity it has attested), so replayed CA, PACE-CAM and
// AA evidence counts towards chip authenticity even without an AA challenge. Do not use it for
// evidence from readers outside the caller's control, such as a public mobile app: a modified
// client can produce CA/PACE-CAM evidence without the chip, or replay earlier AA evidence.
func (v *Verifier) WithTrustedSource() *Verifier {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedSource = true
	return v
}

// Verify parses a serialised document (see DocumentEx.ToCbor), replays its chip authentication
// evidence, and performs passive authentication and Document.Verify.
//
// Verification outcomes are recorded in the returned DocumentEx.Session rather than returned as
// errors; use DocumentEx.Summary() for the overall verdict. The only hard error after parsing is
// an AA nonce that does not match the challenge supplied via WithAAChallenge.
//
// Session.Offline records how the evidence may be trusted (see document.OfflineVerification):
// unless WithTrustedSource is set, Summary().ChipAuthenticity only counts AA bound to a
// WithAAChallenge challenge, not CA/PACE-CAM evidence or unbound AA.
func (v *Verifier) Verify(data []byte) (*document.DocumentEx, error) {
	// Locked for the whole call: see the Verifier docstring above.
	v.mu.Lock()
	defer v.mu.Unlock()

	doc, caBundle, err := document.UnmarshalVerifiableDoc(data)
	if err != nil {
		return nil, fmt.Errorf("[Verify] UnmarshalVerifiableDoc error: %w", err)
	}

	var docEx document.DocumentEx
	docEx.Document = *doc

	if caBundle.PaceCam != nil {
		docEx.Session.PaceCamResult, docEx.Session.PaceErr = pace.VerifyEvidence(doc, caBundle.PaceCam)
	}
	if caBundle.ChipAuth != nil {
		docEx.Session.ChipAuthResult, docEx.Session.ChipAuthErr = chipauth.VerifyEvidence(doc, caBundle.ChipAuth)
	}
	if caBundle.ActiveAuth != nil {
		docEx.Session.ActiveAuthResult, docEx.Session.ActiveAuthErr = activeauth.VerifyEvidence(doc, caBundle.ActiveAuth)
	}

	docEx.Session.Offline = &document.OfflineVerification{TrustedSource: v.trustedSource}

	if v.aaChallenge != nil && caBundle.ActiveAuth != nil {
		if !bytes.Equal(caBundle.ActiveAuth.Nonce, v.aaChallenge) {
			return nil, fmt.Errorf("[Verify] AA nonce mismatch: evidence nonce does not match supplied challenge")
		}
		docEx.Session.Offline.AAChallengeBound = true
	}

	docEx.Session.PassiveAuthResult, docEx.Session.PassiveAuthErr = passiveauth.PassiveAuth(doc, v.cscaCertPool)

	docEx.Session.DocumentVerifyErr = doc.Verify()

	return &docEx, nil
}
