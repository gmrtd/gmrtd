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

	if (secInfos.TotalCnt != 1) || (len(secInfos.PaceInfos) != 1) {
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

	if (secInfos.TotalCnt != 1) || (len(secInfos.ChipAuthPubKeyInfos) != 1) {
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

	if (secInfos.TotalCnt != 1) || (len(secInfos.EfDirInfos) != 1) {
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
	if (secInfos.TotalCnt != 7) ||
		(len(secInfos.PaceInfos) != 2) ||
		(len(secInfos.ChipAuthInfos) != 1) ||
		(len(secInfos.ChipAuthPubKeyInfos) != 2) ||
		(len(secInfos.TermAuthInfos) != 1) ||
		(len(secInfos.UnhandledInfos) != 1) {
		t.Errorf("Security-Info error")
	}
}
