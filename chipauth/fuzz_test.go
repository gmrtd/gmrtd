package chipauth

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
)

// real AT DG14 (brainpoolP256r1 CA key, no key-id), reused from TestChipAuthAT / TestVerifyEvidence
var fuzzCaDg14Bytes = utils.HexToBytes("6E82017E3182017A300D060804007F0007020202020101300F060A04007F000702020302020201013012060A04007F0007020204020202010202010D30820142060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200041983917269AC877C0B61544C2C022000D2A5ABA723E2D80141E648B40911DC3459761F27480E4B57181A53D8FE1190EA86C939AC14363178CAFFC621F0F905C3")

// fixed terminal ephemeral private key from the recorded AT session (TestChipAuthAT)
var fuzzCaTermPri = utils.HexToBytes("80EBAFC8A51BECD4D90BB640EE38C9FD5C12748D28AAA37096B98C4533C4F5F5")

// FuzzVerifyEvidence fuzzes the offline Chip Authentication evidence-replay
// verifier (used e.g. by gmrtd-verify on an externally-supplied, untrusted .gmrtd
// file — no live NFC session). document.ChipAuthEvidence has 4 []byte fields;
// Go's fuzzer doesn't take structs directly, so each is fuzzed as its own
// parameter against a fixed real DG14 (real chip public key), reused from
// TestVerifyEvidence ("AT test data").
func FuzzVerifyEvidence(f *testing.F) {

	doc := &document.Document{}
	if err := doc.NewDG(14, fuzzCaDg14Bytes); err != nil {
		f.Fatalf("NewDG(14, ...) error: %s", err)
	}

	termPri := fuzzCaTermPri
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

// fuzzCaKeyGen stands in for cryptoutils.KeyGeneratorEc with a fixed private key, deriving the
// public key on whichever curve DG14 selects, as the real generator would.
func fuzzCaKeyGen(ec elliptic.Curve) cryptoutils.EcKeypair {
	pri := new(big.Int).Mod(new(big.Int).SetBytes(fuzzCaTermPri), ec.Params().N).Bytes()
	x, y := ec.ScalarBaseMult(pri)
	return cryptoutils.EcKeypair{Pri: pri, Pub: &cryptoutils.EcPoint{X: x, Y: y}}
}

// FuzzDoChipAuth fuzzes a live Chip Authentication session: the chip-supplied DG14 (which selects
// the CA parameters and the chip key used for ECDH) and the chip's MSE:Set AT and GENERAL
// AUTHENTICATE responses. It runs without prior secure messaging so those responses are fuzzed
// as raw bytes rather than mostly failing the MAC check (already covered by iso7816's fuzzers).
// The seed is the recorded AT session (TestChipAuthAT); its final SELECT response is protected
// with the new CA session keys, which the fixed terminal key reproduces, so the seed succeeds.
func FuzzDoChipAuth(f *testing.F) {
	mseRsp := utils.HexToBytes("9000")
	gaRsp := utils.HexToBytes("7C009000")
	selectRsp := utils.HexToBytes("990290008E0803C4B125B4218CEF9000")

	f.Add(fuzzCaDg14Bytes, mseRsp, gaRsp, selectRsp)
	f.Add(fuzzCaDg14Bytes, utils.HexToBytes("6A80"), gaRsp, selectRsp)  // MSE:Set AT rejected
	f.Add(fuzzCaDg14Bytes, mseRsp, utils.HexToBytes("6700"), selectRsp) // extended Le rejected, so CA restarts
	f.Add(fuzzCaDg14Bytes, mseRsp, utils.HexToBytes("9000"), selectRsp) // no 7C tag

	f.Fuzz(func(t *testing.T, dg14, mseRsp, gaRsp, selectRsp []byte) {
		doc := &document.Document{}
		if err := doc.NewDG(14, dg14); err != nil {
			return
		}

		transceiver := &iso7816.SequenceTransceiver{RApdus: [][]byte{mseRsp, gaRsp, selectRsp}}
		chipAuth := NewChipAuth(iso7816.NewNfcSession(transceiver), doc)
		chipAuth.keyGeneratorEc = fuzzCaKeyGen

		_, _ = chipAuth.DoChipAuth()
	})
}
