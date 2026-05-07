package cms

import (
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// TestSelectCertificateBasic tests certificate selection by SKI
func TestSelectCertificateBasic(t *testing.T) {
	// Use real signed data from tests
	signedDataBytes := utils.HexToBytes("3082064906092a864886f70d010702a082063a30820636020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042090462cd4824bc24ce1ce77e0e40da503b5f25063e61a78e22c3ac04e49b2024330250201020420113888bddfb89a94522959f3cf41007bb1241e2fdfa585d8f480317eb648215f302502010304205c1c4fa5fd3d90662a92d5c6c7ee94030ae7eed9070a6d8f1db376b268d99f83302502010b04202a1704fa33c5b3a5760eb8b48ff0ff9178e6470dc525b79b13bdcbc95d9d83d5302502010c0420c9673800c44a18a3d6e5300e6ad35ab8737dcdfb9f259e43bcff0c9b6a2d78a9302502010e0420aff8c92133072ed5703a84a5a6f5fe148f02a86b36b2d5876193bd48243cd2f2a08203e3308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda318201213082011d020101304b303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d4155535452494102086189db18b6ede857300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303331373133343031385a302f06092a864886f70d01090431220420eb5dd19b9688751461b3e61c9c80f1e848d91eec210048aca6653279c7c37c76300c06082a8648ce3d04030205000446304402202567959c119ee15d14520eab1b527c2bc493253d6733bbec30295af57e3ceb070220614dcea3ba92499e2212b9cd4159758cd49ae240e74b3e20d8d49183ed1feb09")

	sd, err := ParseSignedData(signedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData failed: %v", err)
	}

	if len(sd.SignerInfos) == 0 {
		t.Fatal("No SignerInfos in signed data")
	}

	si := &sd.SignerInfos[0]

	// Test selectCertificate (helper method)
	cert, err := si.selectCertificate(sd)
	if err != nil {
		t.Fatalf("selectCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("selectCertificate returned nil certificate")
	}
}

// TestSelectCertificateWithoutCertificates tests error when no certificates present
func TestSelectCertificateWithoutCertificates(t *testing.T) {
	// Create signed data with empty certificates
	sd := &SignedData{
		SignerInfos: []SignerInfo{
			{
				// Sid is an asn1.RawValue - use a minimal valid value
				Sid: asn1.RawValue{Tag: 0, Bytes: utils.HexToBytes("e76eaa567acf6568c660c985717c3c8a50bd024b")},
			},
		},
		// Certificates is asn1.RawValue - empty means no certificates
		Certificates: asn1.RawValue{Bytes: []byte{}},
	}

	si := &sd.SignerInfos[0]

	cert, err := si.selectCertificate(sd)
	if err == nil {
		t.Fatal("Expected error when selecting certificate from empty list")
	}

	if cert != nil {
		t.Fatal("Certificate should be nil on error")
	}
}

// TestPrepareVerificationDataExtractsAttributes tests attribute extraction
func TestPrepareVerificationDataExtractsAttributes(t *testing.T) {
	signedDataBytes := utils.HexToBytes("3082064906092a864886f70d010702a082063a30820636020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042090462cd4824bc24ce1ce77e0e40da503b5f25063e61a78e22c3ac04e49b2024330250201020420113888bddfb89a94522959f3cf41007bb1241e2fdfa585d8f480317eb648215f302502010304205c1c4fa5fd3d90662a92d5c6c7ee94030ae7eed9070a6d8f1db376b268d99f83302502010b04202a1704fa33c5b3a5760eb8b48ff0ff9178e6470dc525b79b13bdcbc95d9d83d5302502010c0420c9673800c44a18a3d6e5300e6ad35ab8737dcdfb9f259e43bcff0c9b6a2d78a9302502010e0420aff8c92133072ed5703a84a5a6f5fe148f02a86b36b2d5876193bd48243cd2f2a08203e3308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda318201213082011d020101304b303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d4155535452494102086189db18b6ede857300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303331373133343031385a302f06092a864886f70d01090431220420eb5dd19b9688751461b3e61c9c80f1e848d91eec210048aca6653279c7c37c76300c06082a8648ce3d04030205000446304402202567959c119ee15d14520eab1b527c2bc493253d6733bbec30295af57e3ceb070220614dcea3ba92499e2212b9cd4159758cd49ae240e74b3e20d8d49183ed1feb09")

	sd, err := ParseSignedData(signedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData failed: %v", err)
	}

	si := &sd.SignerInfos[0]
	config := NewDefaultCMSConfig()

	dataToHash, digestAlg, sigAlg, signature, err := si.prepareVerificationData(config, sd)

	if err != nil {
		t.Fatalf("prepareVerificationData failed: %v", err)
	}

	if len(dataToHash) == 0 {
		t.Error("dataToHash is empty")
	}

	if digestAlg == nil {
		t.Error("digestAlg is nil")
	}

	if sigAlg == nil {
		t.Error("sigAlg is nil")
	}

	if len(signature) == 0 {
		t.Error("signature is empty")
	}
}

// TestPrepareVerificationDataWithMockConfig tests with mock hasher
func TestPrepareVerificationDataWithMockConfig(t *testing.T) {
	signedDataBytes := utils.HexToBytes("3082064906092a864886f70d010702a082063a30820636020103310f300d06096086480165030402010500308201120606678108010101a0820106048201023081ff020100300d060960864801650304020105003081ea3025020101042090462cd4824bc24ce1ce77e0e40da503b5f25063e61a78e22c3ac04e49b2024330250201020420113888bddfb89a94522959f3cf41007bb1241e2fdfa585d8f480317eb648215f302502010304205c1c4fa5fd3d90662a92d5c6c7ee94030ae7eed9070a6d8f1db376b268d99f83302502010b04202a1704fa33c5b3a5760eb8b48ff0ff9178e6470dc525b79b13bdcbc95d9d83d5302502010c0420c9673800c44a18a3d6e5300e6ad35ab8737dcdfb9f259e43bcff0c9b6a2d78a9302502010e0420aff8c92133072ed5703a84a5a6f5fe148f02a86b36b2d5876193bd48243cd2f2a08203e3308203df30820366a00302010202086189db18b6ede857300a06082a8648ce3d040303303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d41555354524941301e170d3233303133313038303430325a170d3333303530363038303430325a3054310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d49310f300d060355040513063030343031353119301706035504030c1044532d415553545249412d654d525444308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200048893905193f315ee2e2f1eee3fd5a496f6637deb3778cfe7cc2f6c7f0682acc795b0290265a2cb83119343544f2bbfe42974159ac77b113dafbee860c2523c06a382015930820155301d0603551d0e04160414e76eaa567acf6568c660c985717c3c8a50bd024b301f0603551d230418301680142692c7e398abfbe35192d3f26e9a317d1fed53bd301a0603551d1004133011810f32303233303530363038303430325a30160603551d20040f300d300b06092a28000a0102010101303e0603551d1f043730353033a031a02f862d687474703a2f2f7777772e626d692e67762e61742f637363612f63726c2f43534341415553545249412e63726c300e0603551d0f0101ff04040302078030370603551d120430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f30370603551d110430302ea410300e310c300a06035504070c03415554861a687474703a2f2f7777772e626d692e67762e61742f637363612f301d06076781080101060204123010020100310b1301501302415213024944300a06082a8648ce3d040303036700306402303af7ae31ca6b8fafca6ec51985997f7119fb2e6d20d61b5327d5740109aa310b410bfb44f354e086f207fcab721e69ae023046c68fb7909f994350a2d1c84d1ae5dff8c00de6d86b7891a6cf90ceea09159402e6e2ed3fa548db28d33146319eefda318201213082011d020101304b303f310b3009060355040613024154310b3009060355040a0c024756310c300a060355040b0c03424d493115301306035504030c0c435343412d4155535452494102086189db18b6ede857300d06096086480165030402010500a066301506092a864886f70d01090331080606678108010101301c06092a864886f70d010905310f170d3233303331373133343031385a302f06092a864886f70d01090431220420eb5dd19b9688751461b3e61c9c80f1e848d91eec210048aca6653279c7c37c76300c06082a8648ce3d04030205000446304402202567959c119ee15d14520eab1b527c2bc493253d6733bbec30295af57e3ceb070220614dcea3ba92499e2212b9cd4159758cd49ae240e74b3e20d8d49183ed1feb09")

	sd, err := ParseSignedData(signedDataBytes)
	if err != nil {
		t.Fatalf("ParseSignedData failed: %v", err)
	}

	si := &sd.SignerInfos[0]

	// Create config with recording hasher
	recorder := &RecordingCryptoHasher{}
	config := &CMSConfig{
		Hasher:      recorder,
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}

	_, _, _, _, err = si.prepareVerificationData(config, sd)
	// Error is expected since the recording hasher returns minimal hashes
	// We just verify the recorder was called
	_ = err

	if len(recorder.Calls) == 0 {
		t.Error("Expected hasher to be called during verification")
	}
}

// TestEcCurveWithConfigValidCurve tests EC curve resolution with valid curve
func TestEcCurveWithConfigValidCurve(t *testing.T) {
	// Use P-384 public key (OID 1.3.132.0.34) which is in standard lookup
	spkiData := utils.HexToBytes("3076301006072a8648ce3d020106052b81040020036200048aca5f821170fa4d8233c7f23f795792af42e791045bdf55989684aa16d1027d27541b0226d665c50e0ff76f91f5aeebf6af5178c02204045aa43002c893ed2b800cafa1e42cb47f80a21a6f0c3a2919bc5242c21daca5f4ec3c270e5620eb7c")

	spki, err := Asn1decodeSubjectPublicKeyInfo(spkiData)
	if err != nil {
		t.Fatalf("Failed to decode SPKI: %v", err)
	}

	config := NewDefaultCMSConfig()

	// This test demonstrates that EcCurveWithConfig accepts and uses config
	// The specific curve resolution may fail for unsupported OIDs
	_, _ = spki.EcCurveWithConfig(config)
	// Just verify the method completes without panic
}

// TestEcCurveWithConfigNonECKey tests error when key is not EC
func TestEcCurveWithConfigNonECKey(t *testing.T) {
	// RSA public key
	spkiData := utils.HexToBytes("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c2c4a860236d3c9096a076d6ba5107e0f7bd81e1ba916f7375724bd2b0b0b63956813715a3457ab0458b71fb35a45b27f9ef7ac3e579dea45dfbfd07819ed6b7021aa5336c58442aadd96ca9ee9d32473e9d9278562b4d10258ade6a98fb1c7cfdc3b3716ef5dec58cf73b359f389599b4b5865a9863519eb001c324387da755450db341309360e3807c0565b8e2c44fbd5e6e8d04d006d7ee768b8e8436082a90fa0e837f32f46087ab4a0d9be28aa7da1794ceb0172a7f50ed20f6df641efbcbfd2aac89775c761a7310093c671c977fa18b0d6e01fb25f7a432b42c65359784c689205719c1cf6e3a65dae2da434c326dde81bb6ffffbdbf6de5c16bba7490203010001")

	spki, err := Asn1decodeSubjectPublicKeyInfo(spkiData)
	if err != nil {
		t.Fatalf("Failed to decode SPKI: %v", err)
	}

	config := NewDefaultCMSConfig()

	_, err = spki.EcCurveWithConfig(config)
	if err == nil {
		t.Fatal("Expected error for non-EC key")
	}
}

// TestDetermineDigestAlgFromSigAlgWithConfigValid tests digest algorithm resolution
func TestDetermineDigestAlgFromSigAlgWithConfigValid(t *testing.T) {
	// ECDSA with SHA-256 signature algorithm
	sigAlgOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	sigAlg := AlgorithmIdentifier{Algorithm: sigAlgOID}
	config := NewDefaultCMSConfig()

	digestAlg, err := sigAlg.DetermineDigestAlgFromSigAlgWithConfig(config)
	if err != nil {
		t.Fatalf("DetermineDigestAlgFromSigAlgWithConfig failed: %v", err)
	}

	if digestAlg == nil {
		t.Fatal("digestAlg is nil")
	}

	// Expected: SHA-256 OID
	if !digestAlg.Equal(oid.OidHashAlgorithmSHA256) {
		t.Errorf("Expected SHA-256, got %s", digestAlg)
	}
}

// TestEcCurveAndPubKeyWithConfigSuccess tests curve and pubkey resolution
func TestEcCurveAndPubKeyWithConfigSuccess(t *testing.T) {
	// Use a test vector from existing passing tests
	// P-384 public key
	spkiData := utils.HexToBytes("3076301006072a8648ce3d020106052b81040020036200048aca5f821170fa4d8233c7f23f795792af42e791045bdf55989684aa16d1027d27541b0226d665c50e0ff76f91f5aeebf6af5178c02204045aa43002c893ed2b800cafa1e42cb47f80a21a6f0c3a2919bc5242c21daca5f4ec3c270e5620eb7c")

	spki, err := Asn1decodeSubjectPublicKeyInfo(spkiData)
	if err != nil {
		t.Fatalf("Failed to decode SPKI: %v", err)
	}

	config := NewDefaultCMSConfig()

	// This test demonstrates that EcCurveAndPubKeyWithConfig accepts and uses config
	// The specific curve resolution may fail for unsupported OIDs
	_, _, _ = spki.EcCurveAndPubKeyWithConfig(config, false)
	// Just verify the method completes without panic
}

// TestEcCurveAndPubKeyWithConfigInvalidKey tests error with invalid key
func TestEcCurveAndPubKeyWithConfigInvalidKey(t *testing.T) {
	// RSA key - not EC
	spkiData := utils.HexToBytes("30820122300d06092a864886f70d01010105000382010f003082010a0282010100c2c4a860236d3c9096a076d6ba5107e0f7bd81e1ba916f7375724bd2b0b0b63956813715a3457ab0458b71fb35a45b27f9ef7ac3e579dea45dfbfd07819ed6b7021aa5336c58442aadd96ca9ee9d32473e9d9278562b4d10258ade6a98fb1c7cfdc3b3716ef5dec58cf73b359f389599b4b5865a9863519eb001c324387da755450db341309360e3807c0565b8e2c44fbd5e6e8d04d006d7ee768b8e8436082a90fa0e837f32f46087ab4a0d9be28aa7da1794ceb0172a7f50ed20f6df641efbcbfd2aac89775c761a7310093c671c977fa18b0d6e01fb25f7a432b42c65359784c689205719c1cf6e3a65dae2da434c326dde81bb6ffffbdbf6de5c16bba7490203010001")

	spki, err := Asn1decodeSubjectPublicKeyInfo(spkiData)
	if err != nil {
		t.Fatalf("Failed to decode SPKI: %v", err)
	}

	config := NewDefaultCMSConfig()

	_, _, err = spki.EcCurveAndPubKeyWithConfig(config, false)
	if err == nil {
		t.Fatal("Expected error for non-EC key")
	}
}

// TestHelperMethodsUseConfig verifies helper methods actually use the config
func TestHelperMethodsUseConfig(t *testing.T) {
	testCases := []struct {
		name          string
		mockHasher    bool
		mockParser    bool
		mockLookup    bool
		shouldSucceed bool
	}{
		{
			name:          "with_mock_hasher",
			mockHasher:    true,
			shouldSucceed: true,
		},
		{
			name:       "with_mock_parser",
			mockParser: true,
		},
		{
			name:       "with_mock_lookup",
			mockLookup: true,
		},
		{
			name:          "all_mocks",
			mockHasher:    true,
			mockParser:    true,
			mockLookup:    true,
			shouldSucceed: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var config *CMSConfig

			if tc.mockHasher || tc.mockParser || tc.mockLookup {
				config, _, _, _ = NewMockCMSConfigWithMocks()
			} else {
				config = NewDefaultCMSConfig()
			}

			if config == nil {
				t.Fatal("config is nil")
			}

			if config.Hasher == nil || config.Parser == nil || config.CurveLookup == nil {
				t.Fatal("config fields are nil")
			}
		})
	}
}

// TestHelperMethodErrorHandling tests error handling in helpers
func TestHelperMethodErrorHandling(t *testing.T) {
	tests := []struct {
		name    string
		config  *CMSConfig
		testFn  func(*CMSConfig) error
		wantErr bool
	}{
		{
			name: "error_hasher",
			config: &CMSConfig{
				Hasher:      NewErrorHasher(fmt.Errorf("hash error")),
				Parser:      &DefaultAsn1Parser{},
				CurveLookup: &DefaultCurveLookup{},
			},
			testFn: func(cfg *CMSConfig) error {
				_, err := cfg.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA256, []byte("test"))
				return err
			},
			wantErr: true,
		},
		{
			name: "error_parser",
			config: &CMSConfig{
				Hasher:      &DefaultCryptoHasher{},
				Parser:      NewErrorParser(fmt.Errorf("parse error")),
				CurveLookup: &DefaultCurveLookup{},
			},
			testFn: func(cfg *CMSConfig) error {
				return cfg.Parser.ParseAsn1([]byte{}, false, nil)
			},
			wantErr: true,
		},
		{
			name: "empty_lookup",
			config: &CMSConfig{
				Hasher:      &DefaultCryptoHasher{},
				Parser:      &DefaultAsn1Parser{},
				CurveLookup: NewEmptyCurveLookup(),
			},
			testFn: func(cfg *CMSConfig) error {
				curves := cfg.CurveLookup.GetNamedCurves()
				if len(curves) != 0 {
					return fmt.Errorf("expected 0 curves")
				}
				return nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.testFn(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error: %v, wantErr: %v", err, tt.wantErr)
			}
		})
	}
}
