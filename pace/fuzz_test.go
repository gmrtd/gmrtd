package pace

import (
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
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

// FuzzDoPACE fuzzes a live PACE session with what a malicious or cloned chip controls before
// secure messaging is established: EF.CardAccess (which selects the PACE algorithm and domain
// parameters) and the R-APDUs for MSE:Set AT and the four GENERAL AUTHENTICATE steps (encrypted
// nonce, mapping, key agreement, and mutual authentication including the CAM ECAD). The seed is
// the recorded DE PACE-CAM session; the EF.CardSecurity reads that follow are served from that
// recording, so an unmodified seed completes PACE-CAM.
func FuzzDoPACE(f *testing.F) {
	var rsp [5][]byte
	for i := range rsp {
		rsp[i] = utils.HexToBytes(deCamRecording[i][1])
	}

	f.Add(deCamCardAccessBytes, rsp[0], rsp[1], rsp[2], rsp[3], rsp[4])
	f.Add(deCamCardAccessBytes, utils.HexToBytes("6A80"), rsp[1], rsp[2], rsp[3], rsp[4])
	f.Add(deCamCardAccessBytes, rsp[0], rsp[1], rsp[2], rsp[3], utils.HexToBytes("7C0A86083ABB9674BCE93C089000")) // GM-style response, no ECAD

	f.Fuzz(func(t *testing.T, cardAccessBytes, mseRsp, nonceRsp, mapRsp, kaRsp, mutualAuthRsp []byte) {
		cardAccess, err := document.NewCardAccess(cardAccessBytes)
		if err != nil {
			return
		}

		transceiver := &iso7816.SequenceTransceiver{
			RApdus:   [][]byte{mseRsp, nonceRsp, mapRsp, kaRsp, mutualAuthRsp},
			Fallback: deCamTransceiver(),
		}
		pace, _ := newDeCamPace(t, transceiver, cardAccess)

		_, _, _ = pace.DoPACE()
	})
}
