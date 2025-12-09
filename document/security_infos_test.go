package document

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
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

	if (secInfos.TotalCnt() != 1) || (len(secInfos.PaceInfos) != 1) {
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

	if (secInfos.TotalCnt() != 1) || (len(secInfos.ChipAuthPubKeyInfos) != 1) {
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

	if (secInfos.TotalCnt() != 1) || (len(secInfos.EfDirInfos) != 1) {
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
	if (secInfos.TotalCnt() != 7) ||
		(len(secInfos.PaceInfos) != 2) ||
		(len(secInfos.ChipAuthInfos) != 1) ||
		(len(secInfos.ChipAuthPubKeyInfos) != 2) ||
		(len(secInfos.TermAuthInfos) != 1) ||
		(len(secInfos.UnhandledInfos) != 1) {
		t.Errorf("Security-Info error")
	}
}

func TestHandlePaceInfoBadAsnErr(t *testing.T) {
	// adapted from valid test data, to be invalid ASN1 (made length +1 byte higher than it should be)
	// oid			: 0.4.0.127.0.7.2.2.4.2.2 (OidPaceEcdhGmAesCbcCmac128)
	// data (orig)	: 3012060a04007f0007020204020202010202010d
	// data (bad)	: 3013060a04007f0007020204020202010202010d

	var oid asn1.ObjectIdentifier = oid.OidPaceEcdhGmAesCbcCmac128
	var data []byte = utils.HexToBytes("3013060a04007f0007020204020202010202010d")

	var secInfos SecurityInfos

	handled, err := handlePaceInfo(oid, data, &secInfos)
	if err == nil {
		t.Fatalf("error expected")
	}
	if handled {
		t.Fatalf("should not be handled")
	}
}

func TestHandleChipAuthenticationInfoBadAsnErr(t *testing.T) {
	// adapted from valid test data, to be invalid ASN1 (made length +1 byte higher than it should be)
	// oid			:0.4.0.127.0.7.2.2.3.2.4 (OidCaEcdhAesCbcCmac256)
	// data (orig)	:300f060a04007f00070202030204020101
	// data (bad)	:3010060a04007f00070202030204020101

	var oid asn1.ObjectIdentifier = oid.OidCaEcdhAesCbcCmac256
	var data []byte = utils.HexToBytes("3010060a04007f00070202030204020101")

	var secInfos SecurityInfos

	handled, err := handleChipAuthenticationInfo(oid, data, &secInfos)
	if err == nil {
		t.Fatalf("error expected")
	}
	if handled {
		t.Fatalf("should not be handled")
	}
}

func TestHandleChipAuthenticationPublicKeyInfoBadAsnErr(t *testing.T) {
	// adapted from valid test data, to be invalid ASN1 (made length +1 byte higher than it should be)
	// oid			:0.4.0.127.0.7.2.2.1.2 (OidPkEcdh)
	// data (orig)	:3062060904007f0007020201023052300c060704007f0007010202010d03420004614cd88b00821a887869d0060b44a9d18789353e8cf7dfbc3f29f79327de30b97b1b2dda0be77f24ad415c327c7b7ab2e9c10b0258f5bcbf90c01825fbdfdef702010d
	// data (bad)	:3063060904007f0007020201023052300c060704007f0007010202010d03420004614cd88b00821a887869d0060b44a9d18789353e8cf7dfbc3f29f79327de30b97b1b2dda0be77f24ad415c327c7b7ab2e9c10b0258f5bcbf90c01825fbdfdef702010d

	var oid asn1.ObjectIdentifier = oid.OidPkEcdh
	var data []byte = utils.HexToBytes("3063060904007f0007020201023052300c060704007f0007010202010d03420004614cd88b00821a887869d0060b44a9d18789353e8cf7dfbc3f29f79327de30b97b1b2dda0be77f24ad415c327c7b7ab2e9c10b0258f5bcbf90c01825fbdfdef702010d")

	var secInfos SecurityInfos

	handled, err := handleChipAuthenticationPublicKeyInfo(oid, data, &secInfos)
	if err == nil {
		t.Fatalf("error expected")
	}
	if handled {
		t.Fatalf("should not be handled")
	}
}

func TestHandleEfDirInfoBadAsnErr(t *testing.T) {
	// adapted from valid test data, to be invalid ASN1 (made length +1 byte higher than it should be)
	// oid			:1.3.27.1.1.13 (OidEfDir)
	// data (orig)	:303506052b1b01010d042c61094f07a000000247100161094f07a000000247200161094f07a000000247200261094f07a0000002472003
	// data (bad)	:303606052b1b01010d042c61094f07a000000247100161094f07a000000247200161094f07a000000247200261094f07a0000002472003

	var oid asn1.ObjectIdentifier = oid.OidEfDir
	var data []byte = utils.HexToBytes("303606052b1b01010d042c61094f07a000000247100161094f07a000000247200161094f07a000000247200261094f07a0000002472003")

	var secInfos SecurityInfos

	handled, err := handleEfDirInfo(oid, data, &secInfos)
	if err == nil {
		t.Fatalf("error expected")
	}
	if handled {
		t.Fatalf("should not be handled")
	}
}

func TestHandleUnsupportedInfoBadAsnErr(t *testing.T) {
	// adapted from valid test data, to be invalid ASN1 (made length +1 byte higher than it should be)
	// oid			:0.4.0.127.0.7.2.2.3.2 (OidCaEcdh)
	// data (orig)	:301c060904007f000702020302300c060704007f0007010202010d020148
	// data (bad)	:301d060904007f000702020302300c060704007f0007010202010d020148

	var oid asn1.ObjectIdentifier = oid.OidCaEcdh
	var data []byte = utils.HexToBytes("301d060904007f000702020302300c060704007f0007010202010d020148")

	var secInfos SecurityInfos

	handled, err := handleUnsupportedInfo(oid, data, &secInfos)
	if err == nil {
		t.Fatalf("error expected")
	}
	if handled {
		t.Fatalf("should not be handled")
	}
}

func TestSecurityInfosContains(t *testing.T) {
	// taken from DG14 file on DE passport
	secInfosBytes := utils.HexToBytes("31820196300D060804007F00070202020201013012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D3013060A04007F00070202030202020101020200C330820146060904007F000702020102308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200047036BC5D0BCF31913B59103BB6F2C0C98C99EF4C19B9517340B76BFE4EE2194C76C3F3314E021D4B092DB5A32AB7D6E297F2FBEAE45AA28DEFC4DA750FEAD54E020200C3")

	secInfos, err := DecodeSecurityInfos(secInfosBytes)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	cardAccessSecInfosBytes := utils.HexToBytes("31283012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D")

	cardAccessSecInfos, err := DecodeSecurityInfos(cardAccessSecInfosBytes)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	if err := secInfos.Contains(cardAccessSecInfos); err != nil {
		t.Fatalf("secInfos should CONTAIN cardAccessSecInfos (err:%s)", err)
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

	if secInfos.Contains(cardAccessSecInfos) == nil {
		t.Error("secInfos should *NOT* CONTAIN cardAccessSecInfos")
	}
}

func TestContainsBadAsnErr(t *testing.T) {
	// adapted from valid test data, to be invalid ASN1 (made length +1 byte higher than it should be)
	//
	// secInfo1-raw (orig):	31820196300d060804007f00070202020201013012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d3013060a04007f00070202030202020101020200c330820146060904007f000702020102308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200047036bc5d0bcf31913b59103bb6f2c0c98c99ef4c19b9517340b76bfe4ee2194c76c3f3314e021d4b092db5a32ab7d6e297f2fbeae45aa28defc4da750fead54e020200c3
	// secInfo1-raw (bad) :	31820197300d060804007f00070202020201013012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d3013060a04007f00070202030202020101020200c330820146060904007f000702020102308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200047036bc5d0bcf31913b59103bb6f2c0c98c99ef4c19b9517340b76bfe4ee2194c76c3f3314e021d4b092db5a32ab7d6e297f2fbeae45aa28defc4da750fead54e020200c3
	//
	// secInfo2-raw (orig): 31283012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d
	// secInfo2-raw (bad) : 31293012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d

	// Note: this test takes account of the fact that 'Contains' will only use the 'RawData'.
	//		 if the behaviour changes, then the test may fail as it makes no effect to populate the structure,
	//		 and can't properly populate anyway given that we're testing 'invalid ASN1' scenarios

	var secInfo1orig SecurityInfos = SecurityInfos{RawData: utils.HexToBytes("31820196300d060804007f00070202020201013012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d3013060a04007f00070202030202020101020200c330820146060904007f000702020102308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200047036bc5d0bcf31913b59103bb6f2c0c98c99ef4c19b9517340b76bfe4ee2194c76c3f3314e021d4b092db5a32ab7d6e297f2fbeae45aa28defc4da750fead54e020200c3")}
	var secInfo1bad SecurityInfos = SecurityInfos{RawData: utils.HexToBytes("31820197300d060804007f00070202020201013012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d3013060a04007f00070202030202020101020200c330820146060904007f000702020102308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200047036bc5d0bcf31913b59103bb6f2c0c98c99ef4c19b9517340b76bfe4ee2194c76c3f3314e021d4b092db5a32ab7d6e297f2fbeae45aa28defc4da750fead54e020200c3")}

	var secInfo2orig SecurityInfos = SecurityInfos{RawData: utils.HexToBytes("31283012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d")}
	var secInfo2bad SecurityInfos = SecurityInfos{RawData: utils.HexToBytes("31293012060a04007f0007020204020202010202010d3012060a04007f0007020204060202010202010d")}

	if secInfo1bad.Contains(&secInfo2orig) == nil {
		t.Fatalf("error expected")
	}

	if secInfo1orig.Contains(&secInfo2bad) == nil {
		t.Fatalf("error expected")
	}
}
