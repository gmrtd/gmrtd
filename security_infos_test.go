package gmrtd

import (
	"bytes"
	"testing"
)

func TestDecodeSecurityInfos(t *testing.T) {
	cardAccessFile := HexToBytes("31143012060A04007F0007020204020202010202010D")

	secInfos := DecodeSecurityInfos(cardAccessFile)

	if len(secInfos.PaceInfos) != 1 {
		t.Errorf("PACEInfo expected")
	} else {
		pi := secInfos.PaceInfos[0]

		if pi.Protocol.String() != "0.4.0.127.0.7.2.2.4.2.2" {
			t.Errorf("Wrong protocol")
		} else if pi.Version != 2 {
			t.Errorf("Wrong version")
		} else if pi.ParameterId != 13 {
			t.Errorf("Wrong parameterId")
		}
	}

	if (len(secInfos.PaceDomainParamInfos) != 0) ||
		(len(secInfos.ActiveAuthInfos) != 0) ||
		(len(secInfos.ChipAuthInfos) != 0) ||
		(len(secInfos.ChipAuthPubKeyInfos) != 0) ||
		(len(secInfos.TermAuthInfos) != 0) ||
		(len(secInfos.EfDirInfos) != 0) ||
		(len(secInfos.UnhandledInfos) != 0) {
		t.Errorf("Unexpected data")
	}
}

func TestDecodeSecurityInfos2(t *testing.T) {
	cardAccessFile := HexToBytes("31643062060904007F0007020201023052300C060704007F0007010202010D034200041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC884D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F02010D")

	secInfos := DecodeSecurityInfos(cardAccessFile)

	if len(secInfos.ChipAuthPubKeyInfos) != 1 {
		t.Errorf("ChipAuthPublicKey info expected")
	} else {
		capki := secInfos.ChipAuthPubKeyInfos[0]

		if capki.Protocol.String() != "0.4.0.127.0.7.2.2.1.2" {
			t.Errorf("Wrong protocol")
		} else if capki.ChipAuthenticationPublicKey.Algorithm.Algorithm.String() != "0.4.0.127.0.7.1.2" {
			t.Errorf("Wrong pub-key algorithm")
		} else if capki.ChipAuthenticationPublicKey.Algorithm.Parameters != 13 {
			t.Errorf("Wrong pub-key parameters")
		} else if !bytes.Equal(capki.ChipAuthenticationPublicKey.SubjectPublicKey.Bytes, HexToBytes("041872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC884D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F")) {
			t.Errorf("Wrong pub-key key")
		} else if capki.KeyId != 13 {
			t.Errorf("Wrong key-id")
		}
	}

	if (len(secInfos.PaceInfos) != 0) ||
		(len(secInfos.PaceDomainParamInfos) != 0) ||
		(len(secInfos.ActiveAuthInfos) != 0) ||
		(len(secInfos.ChipAuthInfos) != 0) ||
		(len(secInfos.TermAuthInfos) != 0) ||
		(len(secInfos.EfDirInfos) != 0) ||
		(len(secInfos.UnhandledInfos) != 0) {
		t.Errorf("Unexpected data")
	}
}
