// Package verifier provides offline verification of machine-readable travel documents (MRTDs)
// by replaying serialised chip authentication evidence and performing passive authentication
// against a CSCA certificate pool.
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

	cscaCertPool cms.CertPool
	aaChallenge  []byte
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

// TODO - need to think about hard errors for PA, and CA.. currently only have hard-error for AA nonce mismatch. Should we also hard-error if PA fails, or CA fails? Or just return the result in the DocumentEx.Session?
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

	if v.aaChallenge != nil && caBundle.ActiveAuth != nil {
		if !bytes.Equal(caBundle.ActiveAuth.Nonce, v.aaChallenge) {
			return nil, fmt.Errorf("[Verify] AA nonce mismatch: evidence nonce does not match supplied challenge")
		}
	}

	docEx.Session.PassiveAuthResult, docEx.Session.PassiveAuthErr = passiveauth.PassiveAuth(doc, v.cscaCertPool)

	docEx.Session.DocumentVerifyErr = doc.Verify()

	return &docEx, nil
}
