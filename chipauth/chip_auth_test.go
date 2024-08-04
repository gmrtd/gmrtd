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

func TestChipAuthAT(t *testing.T) {
	// CA test extracted from actual session with AT passport
	// 		DG14 CA entry         : 0.4.0.127.0.7.2.2.3.2.2 (id-CA-ECDH-AES-CBC-CMAC-128)
	//		DG14 Public Key params: Specified curve for 'brainpoolP256r1'
	//
	// NB no key-id is specified

	dg14bytes := utils.HexToBytes("6E82017E3182017A300D060804007F0007020202020101300F060A04007F000702020302020201013012060A04007F0007020204020202010202010D30820142060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200041983917269AC877C0B61544C2C022000D2A5ABA723E2D80141E648B40911DC3459761F27480E4B57181A53D8FE1190EA86C939AC14363178CAFFC621F0F905C3")

	var err error
	var doc document.Document

	err = doc.NewDG(14, dg14bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var nfc *iso7816.NfcSession
	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// MSE:Set AT
		transceiver.AddReqRsp("0C2241A41D8711015D8F69B1EA365CCE4304970DB12421F38E085340D338128085E700", "990290008E083F5136E82A6C34779000")
		// General Authenticate
		transceiver.AddReqRsp("0C860000608751019E18F1BA79D805379752BB560EB70AAC3CE3BC5AFE2FDD4AEB325CA8B578B4A93B9F66A5DF40005F8E878535251D33DD974AAF77FB858773E5799FA9DC1034E89B1150EC7F0BB3DB4BF37A1B9EA4458A9701008E089D204D950C0B95DB00", "8711010B0A5DFFC7432DE4DEB604291377A05B990290008E08B3384A1F5D1579739000")
		// Select EF (DG14)
		transceiver.AddReqRsp("0CA4020C1D8711011B2EE500E84960DF7F37AFE7ADFF53838E084500F3B43E192A5700", "990290008E0803C4B125B4218CEF9000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup SM (and SSC)
	nfc.SM, err = iso7816.NewSecureMessaging(cryptoutils.AES, utils.HexToBytes("524170DE3419B7AF2F23E45AD6EF9595"), utils.HexToBytes("97893F5FDC29A5C13A924FE7D8ED44FD"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	nfc.SM.SetSSC(utils.HexToBytes("000000000000000000000000000000F0"))

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) cryptoutils.EcKeypair {
		var idx int

		return func(ec elliptic.Curve) cryptoutils.EcKeypair {
			var tmpPri *big.Int
			var tmpPub *cryptoutils.EcPoint = new(cryptoutils.EcPoint)

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("80EBAFC8A51BECD4D90BB640EE38C9FD5C12748D28AAA37096B98C4533C4F5F5", 16)
				tmpPub.X, _ = new(big.Int).SetString("4827C781BE1AC7A00B351214FD783AC76D99E831A6316C8FD6DE7BD96CFA31DA", 16)
				tmpPub.Y, _ = new(big.Int).SetString("06B6B57BA380789729F4A028212A768C49BF5F97D98B1DB12BEEC1A1CD324FB2", 16)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return cryptoutils.EcKeypair{Pri: tmpPri.Bytes(), Pub: tmpPub}
		}
	}

	chipAuth := NewChipAuth()

	chipAuth.keyGeneratorEc = getTestKeyGenEc()

	err = chipAuth.DoChipAuth(nfc, &doc)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify CA status reflects that CA was performed
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_CA {
		t.Errorf("CA status not reflecting CA (Exp:%d, Act:%d)", document.CHIP_AUTH_STATUS_CA, doc.ChipAuthStatus)
	}

	var smExp *iso7816.SecureMessaging
	{
		smExp, err = iso7816.NewSecureMessaging(cryptoutils.AES, utils.HexToBytes("C8E27260EFD3F318D18C080CBF11C7E6"), utils.HexToBytes("A942190365204A21409EB28B52BF9160"))
		if err != nil {
			t.Errorf("Unable to setup smExp")
		}
		smExp.SetSSC(utils.HexToBytes("00000000000000000000000000000002"))
	}

	// verify the post Secure-Messaging state (as this truly indicates whether it worked)
	if !nfc.SM.Equal(*smExp) {
		t.Errorf("SM (Post) state differs to expected")
	}
}

func TestChipAuthDE(t *testing.T) {
	// CA test extracted from actual session with AT passport
	// 		DG14 CA entry         : 0.4.0.127.0.7.2.2.3.2.2 (id-CA-ECDH-AES-CBC-CMAC-128)
	//		DG14 Public Key params: Specified curve for 'brainpoolP256r1'
	//
	// NB key-id is specified - so public-key needs to be matching also using key-id

	dg14bytes := utils.HexToBytes("6E82019A31820196300D060804007F00070202020201013012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D3013060A04007F00070202030202020101020200C330820146060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200047036BC5D0BCF31913B59103BB6F2C0C98C99EF4C19B9517340B76BFE4EE2194C76C3F3314E021D4B092DB5A32AB7D6E297F2FBEAE45AA28DEFC4DA750FEAD54E020200C3")

	var err error
	var doc document.Document

	err = doc.NewDG(14, dg14bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var nfc *iso7816.NfcSession
	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// MSE:Set AT
		transceiver.AddReqRsp("0C2241A41D871101980953D37F67558690045D78A853B18A8E08929767A2CEF172E200", "990290008E08FC873EBB62219C8A9000")
		// General Authenticate
		transceiver.AddReqRsp("0C8600006087510161912C367A6322D24AA1D4522DC47A7345369257672DF1D1163D506EB6489395D8083FAD393A394297CE8703C42F22C864C1F4C8E70EE1CF9B497ACF6579190D90F36CF9E16FE2149FF57247285D9E1E9701008E08A1D7A16EFBFD932C00", "87110123E7159AC9B0EF92CE1F6755B89697E3990290008E088972F1595E1508C29000")
		// Select EF (DG14)
		transceiver.AddReqRsp("0CA4020C1D871101FAD37EADBCDE7E6A0833035A9FFF5B708E0836560BBCE1FECD5F00", "990290008E0829D0E1EBBB61BE7A9000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup SM (and SSC)
	nfc.SM, err = iso7816.NewSecureMessaging(cryptoutils.AES, utils.HexToBytes("CC86415F2ED7E8FD663B754265695AE1"), utils.HexToBytes("581E84B8EE06C4D3EEE30461498D7FB3"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	nfc.SM.SetSSC(utils.HexToBytes("000000000000000000000000000000BA"))

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) cryptoutils.EcKeypair {
		var idx int

		return func(ec elliptic.Curve) cryptoutils.EcKeypair {
			var tmpPri *big.Int
			var tmpPub *cryptoutils.EcPoint = new(cryptoutils.EcPoint)

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("84A5145885678EE9307C28C52736896267511203B7B8009C5FE27ABCBAECDCAA", 16)
				tmpPub.X, _ = new(big.Int).SetString("897FA47C895D35949A8DB8F776A62D775BDF764A1AA1BDC2D8FC96CD5C2E80E3", 16)
				tmpPub.Y, _ = new(big.Int).SetString("9F631C67E84364DCF85F5C9F8CE79A752071896819A0D510CF9701652486817C", 16)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return cryptoutils.EcKeypair{Pri: tmpPri.Bytes(), Pub: tmpPub}
		}
	}

	chipAuth := NewChipAuth()

	chipAuth.keyGeneratorEc = getTestKeyGenEc()

	err = chipAuth.DoChipAuth(nfc, &doc)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify CA status reflects that CA was performed
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_CA {
		t.Errorf("CA status not reflecting CA (Exp:%d, Act:%d)", document.CHIP_AUTH_STATUS_CA, doc.ChipAuthStatus)
	}

	var smExp *iso7816.SecureMessaging
	{
		smExp, err = iso7816.NewSecureMessaging(cryptoutils.AES, utils.HexToBytes("AF0EEDB52E87B945FC5503B1C6875C1C"), utils.HexToBytes("CEB85BEDCECFF1DD1E25DFB672C4A5BF"))
		if err != nil {
			t.Errorf("Unable to setup smExp")
		}
		smExp.SetSSC(utils.HexToBytes("00000000000000000000000000000002"))
	}

	// verify the post Secure-Messaging state (as this truly indicates whether it worked)
	if !nfc.SM.Equal(*smExp) {
		t.Errorf("SM (Post) state differs to expected")
	}
}

func TestChipAuthMY(t *testing.T) {
	// CA test extracted from actual session with MY passport
	// 		DG14 CA entry         : 0.4.0.127.0.7.2.2.3.2.1 (id-CA-ECDH-3DES-CBC-CBC)
	//		DG14 Public Key params: Specified curve for 'brainpoolP256r1'
	//
	// NB no key-id is specified

	dg14bytes := utils.HexToBytes("6E82016A3182016630820142060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A702010103420004A04F85AFDFC316FB5E9F33F94CA45837D20D9D91AD5002307C3F124B6EF5B92565D018A6B7F69DB73976BFBB4278757405C64E96104D161649E8A94078EAEFCE300F060A04007F00070202030201020101300D060804007F0007020202020101")

	var err error
	var doc document.Document

	err = doc.NewDG(14, dg14bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var nfc *iso7816.NfcSession
	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// MSE:Set AT
		transceiver.AddReqRsp("0C2241A41D8711019D1E70C6F5EE06A7CA1E98FBF5C945C98E087AC379DC78702E6300", "990290008E08643C2C3AC66585E49000")
		// General Authenticate
		transceiver.AddReqRsp("0C86000058874901A9C6BF370C62AA43CA1EC9B97071727654822361DEB8BA4E5719AA05D8E86AA36164DFA5E506DBF60DC7418858179FD25DAC5E9E49393DDE37E29652444941B562142AB5F19AEA919701008E085083316637060C4D00", "87090108166157B375BC1E990290008E08FF8A254C50179F519000")
		// Select EF (DG14)
		transceiver.AddReqRsp("0CA4020C1587090106904D37288D69488E08A13B74E87B87E44600", "990290008E08C2BF01FDDD1D599D9000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup SM (and SSC)
	nfc.SM, err = iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("896de34a942c7076fec207207acb79c2"), utils.HexToBytes("d6c47ff4677ac8ae91cb49f4ce673432"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	nfc.SM.SetSSC(utils.HexToBytes("9646c154bfb7be79"))

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) cryptoutils.EcKeypair {
		var idx int

		return func(ec elliptic.Curve) cryptoutils.EcKeypair {
			var tmpPri *big.Int
			var tmpPub *cryptoutils.EcPoint = new(cryptoutils.EcPoint)

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("3a31f4e18418312fcb40f3efbe719182c046a9719e1ed8c376197aa9e8ed7465", 16)
				tmpPub.X, _ = new(big.Int).SetString("3da6d3b923689b96aa65d744f1bd1537fcf1f8a5dd9bc6b01d7b30fc1812645b", 16)
				tmpPub.Y, _ = new(big.Int).SetString("510cb66bed899c67a802a7881313e4bca87055cde3cf615efdbadbb64bc32462", 16)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return cryptoutils.EcKeypair{Pri: tmpPri.Bytes(), Pub: tmpPub}
		}
	}

	chipAuth := NewChipAuth()

	chipAuth.keyGeneratorEc = getTestKeyGenEc()

	err = chipAuth.DoChipAuth(nfc, &doc)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify CA status reflects that CA was performed
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_CA {
		t.Errorf("CA status not reflecting CA (Exp:%d, Act:%d)", document.CHIP_AUTH_STATUS_CA, doc.ChipAuthStatus)
	}

	var smExp *iso7816.SecureMessaging
	{
		smExp, err = iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("75b95468910849cdf1a1a2ae5452ce9b"), utils.HexToBytes("cd0bef85d5a82a7ae0fbc12368a41fef"))
		if err != nil {
			t.Errorf("Unable to setup smExp")
		}
		smExp.SetSSC(utils.HexToBytes("0000000000000002"))
	}

	// verify the post Secure-Messaging state (as this truly indicates whether it worked)
	if !nfc.SM.Equal(*smExp) {
		t.Errorf("SM (Post) state differs to expected")
	}
}
