package document

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestDecodeSecurityInfos(t *testing.T) {
	cardAccessFile := utils.HexToBytes("31143012060A04007F0007020204020202010202010D")

	secInfos, err := DecodeSecurityInfos(cardAccessFile)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if len(secInfos.PaceInfos) != 1 {
		t.Errorf("PACEInfo expected")
	} else {
		pi := secInfos.PaceInfos[0]

		if pi.Protocol.String() != "0.4.0.127.0.7.2.2.4.2.2" {
			t.Errorf("Wrong protocol")
		} else if pi.Version != 2 {
			t.Errorf("Wrong version")
		} else if pi.ParameterId.Int64() != 13 {
			t.Errorf("Wrong parameterId")
		}
	}

	if (secInfos.GetTotalCnt() != 1) || (len(secInfos.PaceInfos) != 1) {
		t.Errorf("Security-Info error")
	}
}

func TestDecodeSecurityInfos2(t *testing.T) {
	cardAccessFile := utils.HexToBytes("31643062060904007F0007020201023052300C060704007F0007010202010D034200041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC884D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F02010D")

	secInfos, err := DecodeSecurityInfos(cardAccessFile)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if len(secInfos.ChipAuthPubKeyInfos) != 1 {
		t.Errorf("ChipAuthPublicKey info expected")
	} else {
		capki := secInfos.ChipAuthPubKeyInfos[0]

		if capki.Protocol.String() != "0.4.0.127.0.7.2.2.1.2" {
			t.Errorf("Wrong protocol")
		} else if capki.ChipAuthenticationPublicKey.Algorithm.Algorithm.String() != "0.4.0.127.0.7.1.2" {
			t.Errorf("Wrong pub-key algorithm")
		} else if utils.BytesToInt(capki.ChipAuthenticationPublicKey.Algorithm.Parameters.Bytes) != 13 {
			t.Errorf("Wrong pub-key parameters")
		} else if !bytes.Equal(capki.ChipAuthenticationPublicKey.SubjectPublicKey.Bytes, utils.HexToBytes("041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC884D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F")) {
			t.Errorf("Wrong pub-key key")
		} else if capki.KeyId.Int64() != 13 {
			t.Errorf("Wrong key-id")
		}
	}

	if (secInfos.GetTotalCnt() != 1) || (len(secInfos.ChipAuthPubKeyInfos) != 1) {
		t.Errorf("Security-Info error")
	}
}

func TestDecodeSecurityInfosEfDir(t *testing.T) {
	// EF.DIR (1.3.27.1.1.13)
	// 3137303506052B1B01010D042C61094F07A000000247100161094F07A000000247200161094F07A000000247200261094F07A0000002472003
	cardAccessFile := utils.HexToBytes("3137303506052B1B01010D042C61094F07A000000247100161094F07A000000247200161094F07A000000247200261094F07A0000002472003")

	secInfos, err := DecodeSecurityInfos(cardAccessFile)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if (secInfos.GetTotalCnt() != 1) || (len(secInfos.EfDirInfos) != 1) {
		t.Errorf("Security-Info error")
	}

}

func TestDecodeSecurityInfosCardSecFile(t *testing.T) {
	// taken from CardSecurity file on DE passport
	cardAccessFile := utils.HexToBytes("31820131300d060804007f00070202020201023012060a04007f000702020302020201020201483012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d301c060904007f000702020302300c060704007f0007010202010d0201483062060904007f0007020201023052300c060704007f0007010202010d03420004614cd88b00821a887869d0060b44a9d18789353e8cf7dfbc3f29f79327de30b97b1b2dda0be77f24ad415c327c7b7ab2e9c10b0258f5bcbf90c01825fbdfdef702010d3062060904007f0007020201023052300c060704007f0007010202010d034200048488a2dc34b6b36d6c01a8dfbd70a874610c53b32893a1de3b1c4bbf477eef3761aa51dfd6b52da43587e95386fc34ffe178d90086a7d646047c82bebc27da3e020148")

	secInfos, err := DecodeSecurityInfos(cardAccessFile)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// NB test data includes an unhandled sec-info, where id-CA-ECDH (0.4.0.127.0.7.2.2.3.2) is incorrectly specified (from DE passport)
	if (secInfos.GetTotalCnt() != 7) ||
		(len(secInfos.PaceInfos) != 2) ||
		(len(secInfos.ChipAuthInfos) != 1) ||
		(len(secInfos.ChipAuthPubKeyInfos) != 2) ||
		(len(secInfos.TermAuthInfos) != 1) ||
		(len(secInfos.UnhandledInfos) != 1) {
		t.Errorf("Security-Info error")
	}
}

//

func TestSecurityInfosContains(t *testing.T) {
	// taken from DG14 file on DE passport
	secInfosBytes := utils.HexToBytes("31820196300D060804007F00070202020201013012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D3013060A04007F00070202030202020101020200C330820146060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200047036BC5D0BCF31913B59103BB6F2C0C98C99EF4C19B9517340B76BFE4EE2194C76C3F3314E021D4B092DB5A32AB7D6E297F2FBEAE45AA28DEFC4DA750FEAD54E020200C3")

	secInfos, err := DecodeSecurityInfos(secInfosBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	cardAccessSecInfosBytes := utils.HexToBytes("31283012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D")

	cardAccessSecInfos, err := DecodeSecurityInfos(cardAccessSecInfosBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !secInfos.Contains(cardAccessSecInfos) {
		t.Error("secInfos should CONTAIN cardAccessSecInfos")
	}
}

func TestSecurityInfosContainsError(t *testing.T) {
	// taken from DG14 file on DE passport
	secInfosBytes := utils.HexToBytes("31820196300D060804007F00070202020201013012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D3013060A04007F00070202030202020101020200C330820146060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200047036BC5D0BCF31913B59103BB6F2C0C98C99EF4C19B9517340B76BFE4EE2194C76C3F3314E021D4B092DB5A32AB7D6E297F2FBEAE45AA28DEFC4DA750FEAD54E020200C3")

	secInfos, err := DecodeSecurityInfos(secInfosBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// NB modified to reference param:0x0C (was 0x0D)
	// orig: 31283012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D
	// mod : 31283012060A04007F0007020204020202010202010C3012060A04007F0007020204060202010202010D
	cardAccessSecInfosBytes := utils.HexToBytes("31283012060A04007F0007020204020202010202010C3012060A04007F0007020204060202010202010D")

	cardAccessSecInfos, err := DecodeSecurityInfos(cardAccessSecInfosBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if secInfos.Contains(cardAccessSecInfos) {
		t.Error("secInfos should *NOT* CONTAIN cardAccessSecInfos")
	}
}
