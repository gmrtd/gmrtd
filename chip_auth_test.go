package gmrtd

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"
)

// TODO - MY.. others? finland IC?

func TestChipAuthAT(t *testing.T) {
	// CA test extracted from actual session with AT passport
	// 		DG14 CA entry         : 0.4.0.127.0.7.2.2.3.2.2 (id-CA-ECDH-AES-CBC-CMAC-128)
	//		DG14 Public Key params: Specified curve for 'brainpoolP256r1'

	dg14bytes := HexToBytes("6E82017E3182017A300D060804007F0007020202020101300F060A04007F000702020302020201013012060A04007F0007020204020202010202010D30820142060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200041983917269AC877C0B61544C2C022000D2A5ABA723E2D80141E648B40911DC3459761F27480E4B57181A53D8FE1190EA86C939AC14363178CAFFC621F0F905C3")

	var err error
	var doc Document

	err = doc.NewDG(14, dg14bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var nfc *NfcSession
	{
		var transceiver *MockTransceiver = new(MockTransceiver)

		// MSE:Set AT
		transceiver.AddReqRsp("0C2241A41D8711015D8F69B1EA365CCE4304970DB12421F38E085340D338128085E700", "990290008E083F5136E82A6C34779000")
		// General Authenticate
		transceiver.AddReqRsp("0C860000608751019E18F1BA79D805379752BB560EB70AAC3CE3BC5AFE2FDD4AEB325CA8B578B4A93B9F66A5DF40005F8E878535251D33DD974AAF77FB858773E5799FA9DC1034E89B1150EC7F0BB3DB4BF37A1B9EA4458A9701008E089D204D950C0B95DB00", "8711010B0A5DFFC7432DE4DEB604291377A05B990290008E08B3384A1F5D1579739000")
		// Select EF (DG14)
		transceiver.AddReqRsp("0CA4020C1D8711011B2EE500E84960DF7F37AFE7ADFF53838E084500F3B43E192A5700", "990290008E0803C4B125B4218CEF9000")

		nfc = NewNfcSession(transceiver)
	}

	// setup SM (and SSC)
	nfc.sm, err = NewSecureMessaging(AES, HexToBytes("524170DE3419B7AF2F23E45AD6EF9595"), HexToBytes("97893F5FDC29A5C13A924FE7D8ED44FD"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	nfc.sm.SetSSC(HexToBytes("000000000000000000000000000000F0"))

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) ([]byte, *EC_POINT) {
		var idx int

		return func(ec elliptic.Curve) (pri []byte, pub *EC_POINT) {
			var tmpPri *big.Int
			var tmpPub EC_POINT

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("80EBAFC8A51BECD4D90BB640EE38C9FD5C12748D28AAA37096B98C4533C4F5F5", 16)
				tmpPub.x, _ = new(big.Int).SetString("4827C781BE1AC7A00B351214FD783AC76D99E831A6316C8FD6DE7BD96CFA31DA", 16)
				tmpPub.y, _ = new(big.Int).SetString("06B6B57BA380789729F4A028212A768C49BF5F97D98B1DB12BEEC1A1CD324FB2", 16)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return tmpPri.Bytes(), &tmpPub
		}
	}

	chipAuth := NewChipAuth()

	chipAuth.keyGeneratorEc = getTestKeyGenEc()

	err = chipAuth.doChipAuth(nfc, &doc)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify CA status reflects that CA was performed
	if doc.ChipAuthStatus != CHIP_AUTH_STATUS_CA {
		t.Errorf("CA status not reflecting CA (Exp:%d, Act:%d)", CHIP_AUTH_STATUS_CA, doc.ChipAuthStatus)
	}

	// verify the post Secure-Messaging state (as this truly indicates whether it worked)
	if (nfc.sm.alg != 2) ||
		!bytes.Equal(nfc.sm.KSenc, HexToBytes("C8E27260EFD3F318D18C080CBF11C7E6")) ||
		!bytes.Equal(nfc.sm.KSmac, HexToBytes("A942190365204A21409EB28B52BF9160")) ||
		!bytes.Equal(nfc.sm.SSC, HexToBytes("00000000000000000000000000000002")) {
		t.Errorf("SM (Post) state differs to expected")
	}
}

// TODO - MY passport has CA with TDES... good to add

// TODO - should have UTs for doECDH.. better in crypto than PACE
