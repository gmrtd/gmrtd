// Package verifier provides offline verification of machine-readable travel documents (MRTDs)
// by replaying serialised chip authentication evidence and performing passive authentication
// against a CSCA certificate pool.
package verifier

import (
	"fmt"

	"github.com/gmrtd/gmrtd/activeauth"
	"github.com/gmrtd/gmrtd/chipauth"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/pace"
	"github.com/gmrtd/gmrtd/passiveauth"
)

type Verifier struct {
	cscaCertPool cms.CertPool
}

func NewVerifier(cscaCertPool cms.CertPool) *Verifier {
	return &Verifier{cscaCertPool: cscaCertPool}
}

func (v *Verifier) Verify(data []byte) (*document.DocumentEx, error) {
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

	docEx.Session.PassiveAuthResult, docEx.Session.PassiveAuthErr = passiveauth.PassiveAuth(doc, v.cscaCertPool)

	docEx.GenerateSummary()

	return &docEx, nil
}
