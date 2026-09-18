package chipauth

import (
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/utils"
)

// FuzzVerifyEvidence fuzzes the offline Chip Authentication evidence-replay
// verifier (used e.g. by gmrtd-verify on an externally-supplied, untrusted .gmrtd
// file — no live NFC session). document.ChipAuthEvidence has 4 []byte fields;
// Go's fuzzer doesn't take structs directly, so each is fuzzed as its own
// parameter against a fixed real DG14 (real chip public key), reused from
// TestVerifyEvidence ("AT test data").
func FuzzVerifyEvidence(f *testing.F) {
	dg14bytes := utils.HexToBytes("6E82017E3182017A300D060804007F0007020202020101300F060A04007F000702020302020201013012060A04007F0007020204020202010202010D30820142060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200041983917269AC877C0B61544C2C022000D2A5ABA723E2D80141E648B40911DC3459761F27480E4B57181A53D8FE1190EA86C939AC14363178CAFFC621F0F905C3")

	doc := &document.Document{}
	if err := doc.NewDG(14, dg14bytes); err != nil {
		f.Fatalf("NewDG(14, ...) error: %s", err)
	}

	termPri := utils.HexToBytes("80EBAFC8A51BECD4D90BB640EE38C9FD5C12748D28AAA37096B98C4533C4F5F5")
	termPubKey := utils.HexToBytes("044827C781BE1AC7A00B351214FD783AC76D99E831A6316C8FD6DE7BD96CFA31DA06B6B57BA380789729F4A028212A768C49BF5F97D98B1DB12BEEC1A1CD324FB2")
	smRapdu := utils.HexToBytes("990290008E0803C4B125B4218CEF9000")
	smSsc := utils.HexToBytes("00000000000000000000000000000002")

	f.Add(termPri, termPubKey, smRapdu, smSsc)
	f.Add([]byte(nil), []byte(nil), []byte(nil), []byte(nil))
	f.Add(termPri, termPubKey, utils.HexToBytes("990269828E0870AD2E8835E91DEA6982"), smSsc) // non-9000 status
	f.Add(termPri, termPubKey, smRapdu, make([]byte, 20))                                   // oversized SmSsc (see TestVerifyEvidence/oversized_SmSsc_does_not_panic)

	f.Fuzz(func(t *testing.T, termPri, termPubKey, smRapdu, smSsc []byte) {
		_, _ = VerifyEvidence(doc, &document.ChipAuthEvidence{
			TermPri:    termPri,
			TermPubKey: termPubKey,
			SmRapdu:    smRapdu,
			SmSsc:      smSsc,
		})
	})
}
