package pace

import (
	"testing"

	"github.com/gmrtd/gmrtd/document"
)

// FuzzVerifyEvidence fuzzes the offline PACE-CAM evidence-replay verifier (used
// e.g. by gmrtd-verify on an externally-supplied, untrusted .gmrtd file — no live
// NFC session). document.PaceCamEvidence has 8 []byte fields; Go's fuzzer doesn't
// take structs directly, so each is fuzzed as its own parameter against a fixed
// real Document (via setupDeCamEvidence, a full recorded PACE-CAM session already
// used by this package's own VerifyEvidence tests). PaceOid/ParameterId are kept
// fixed to the real captured values - they're protocol negotiation parameters
// sanity-checked against the document's own CardAccess, not raw untrusted crypto
// material like the byte fields are.
func FuzzVerifyEvidence(f *testing.F) {
	doc, evidence := setupDeCamEvidence(f)

	f.Add(evidence.Nonce, evidence.TermMapPri, evidence.TermMapPub, evidence.ChipMapPub,
		evidence.TermKaPri, evidence.TermKaPub, evidence.ChipKaPub, evidence.EcadIC)
	f.Add([]byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil), []byte(nil))

	f.Fuzz(func(t *testing.T, nonce, termMapPri, termMapPub, chipMapPub, termKaPri, termKaPub, chipKaPub, ecadIC []byte) {
		fuzzed := &document.PaceCamEvidence{
			PaceOid:     evidence.PaceOid,
			ParameterId: evidence.ParameterId,
			Nonce:       nonce,
			TermMapPri:  termMapPri,
			TermMapPub:  termMapPub,
			ChipMapPub:  chipMapPub,
			TermKaPri:   termKaPri,
			TermKaPub:   termKaPub,
			ChipKaPub:   chipKaPub,
			EcadIC:      ecadIC,
		}
		_, _ = VerifyEvidence(doc, fuzzed)
	})
}
