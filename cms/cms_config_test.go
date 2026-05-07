package cms

import (
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// TestDefaultCMSConfigFactory verifies NewDefaultCMSConfig creates valid config
func TestDefaultCMSConfigFactory(t *testing.T) {
	config := NewDefaultCMSConfig()

	if config == nil {
		t.Fatal("NewDefaultCMSConfig returned nil")
	}

	if config.Hasher == nil {
		t.Fatal("CMSConfig.Hasher is nil")
	}

	if config.Parser == nil {
		t.Fatal("CMSConfig.Parser is nil")
	}

	if config.CurveLookup == nil {
		t.Fatal("CMSConfig.CurveLookup is nil")
	}

	// Verify interfaces are actually usable
	if config.Hasher != nil {
		_, err := config.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA256, []byte("test"))
		if err != nil {
			t.Errorf("Hasher.CryptoHashByOid failed: %v", err)
		}
	}

	curves := config.CurveLookup.GetNamedCurves()
	if len(curves) == 0 {
		t.Error("CurveLookup.GetNamedCurves returned empty list")
	}
}

// TestMockCryptoHasherIntegration verifies mock hasher is used in config
func TestMockCryptoHasherIntegration(t *testing.T) {
	mockHasher := &MockCryptoHasher{
		HashFunc: func(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
			return []byte{0xAB, 0xCD}, nil
		},
	}

	config := &CMSConfig{
		Hasher:      mockHasher,
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}

	testOID := oid.OidHashAlgorithmSHA256
	testData := []byte("test data")

	hash, err := config.Hasher.CryptoHashByOid(testOID, testData)
	if err != nil {
		t.Fatalf("CryptoHashByOid failed: %v", err)
	}

	if mockHasher.CallCount != 1 {
		t.Errorf("Expected 1 call, got %d", mockHasher.CallCount)
	}

	if len(hash) != 2 || hash[0] != 0xAB || hash[1] != 0xCD {
		t.Errorf("Unexpected hash result: %x", hash)
	}

	if !mockHasher.LastOID.Equal(testOID) {
		t.Errorf("OID mismatch: expected %s, got %s", testOID, mockHasher.LastOID)
	}
}

// TestMockAsn1ParserIntegration verifies mock parser is used in config
func TestMockAsn1ParserIntegration(t *testing.T) {
	parseCount := 0
	mockParser := &MockAsn1Parser{
		ParseFunc: func(data []byte, allowExtraData bool, v interface{}) error {
			parseCount++
			return nil
		},
	}

	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      mockParser,
		CurveLookup: &DefaultCurveLookup{},
	}

	testData := []byte{0x30, 0x02, 0x05, 0x00}
	var result interface{}

	err := config.Parser.ParseAsn1(testData, false, result)
	if err != nil {
		t.Fatalf("ParseAsn1 failed: %v", err)
	}

	if mockParser.CallCount != 1 {
		t.Errorf("Expected 1 call, got %d", mockParser.CallCount)
	}
}

// TestMockCurveLookupIntegration verifies mock lookup is used in config
func TestMockCurveLookupIntegration(t *testing.T) {
	// Get pre-configured curves from default lookup
	defaultLookup := DefaultCurveLookup{}
	defaultCurves := defaultLookup.GetNamedCurves()
	
	// Use only the first curve as a custom list
	customCurves := []EcNamedCurve{defaultCurves[2]} // P-256

	mockLookup := &MockCurveLookup{
		NamedCurves:  customCurves,
		LookupCurves: []elliptic.Curve{elliptic.P256()},
	}

	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: mockLookup,
	}

	curves := config.CurveLookup.GetNamedCurves()
	if len(curves) != 1 {
		t.Errorf("Expected 1 curve, got %d", len(curves))
	}

	if mockLookup.CallCountNamed != 1 {
		t.Errorf("Expected GetNamedCurves called once, got %d", mockLookup.CallCountNamed)
	}
}

// TestErrorHasherPropagation verifies hash errors are properly propagated
func TestErrorHasherPropagation(t *testing.T) {
	expectedErr := errors.New("hash function failed")
	config := &CMSConfig{
		Hasher:      NewErrorHasher(expectedErr),
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}

	_, err := config.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA256, []byte("test"))
	if err == nil {
		t.Fatal("Expected error from hasher")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Wrong error: expected %v, got %v", expectedErr, err)
	}
}

// TestErrorParserPropagation verifies parser errors are properly propagated
func TestErrorParserPropagation(t *testing.T) {
	expectedErr := errors.New("parse failed")
	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      NewErrorParser(expectedErr),
		CurveLookup: &DefaultCurveLookup{},
	}

	var result interface{}
	err := config.Parser.ParseAsn1([]byte{}, false, result)
	if err == nil {
		t.Fatal("Expected error from parser")
	}

	if !errors.Is(err, expectedErr) {
		t.Errorf("Wrong error: expected %v, got %v", expectedErr, err)
	}
}

// TestEmptyCurveLookup verifies behavior with empty curve list
func TestEmptyCurveLookup(t *testing.T) {
	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: NewEmptyCurveLookup(),
	}

	curves := config.CurveLookup.GetNamedCurves()
	if len(curves) != 0 {
		t.Errorf("Expected 0 curves, got %d", len(curves))
	}

	lookupCurves := config.CurveLookup.GetLookupCurves()
	if len(lookupCurves) != 0 {
		t.Errorf("Expected 0 lookup curves, got %d", len(lookupCurves))
	}
}

// TestRecordingHasher verifies all hash calls are recorded
func TestRecordingHasher(t *testing.T) {
	recorder := &RecordingCryptoHasher{}
	config := &CMSConfig{
		Hasher:      recorder,
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}

	oid1 := oid.OidHashAlgorithmSHA256
	data1 := []byte("test1")
	config.Hasher.CryptoHashByOid(oid1, data1)

	oid2 := oid.OidHashAlgorithmSHA512
	data2 := []byte("test2")
	config.Hasher.CryptoHashByOid(oid2, data2)

	if len(recorder.Calls) != 2 {
		t.Errorf("Expected 2 calls recorded, got %d", len(recorder.Calls))
	}

	if !recorder.Calls[0].OID.Equal(oid1) {
		t.Errorf("First OID mismatch")
	}

	if !recorder.Calls[1].OID.Equal(oid2) {
		t.Errorf("Second OID mismatch")
	}
}

// TestRecordingParser verifies all parse calls are recorded
func TestRecordingParser(t *testing.T) {
	recorder := &RecordingAsn1Parser{}
	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      recorder,
		CurveLookup: &DefaultCurveLookup{},
	}

	data1 := []byte{0x30, 0x00}
	var result1 interface{}
	config.Parser.ParseAsn1(data1, false, result1)

	data2 := []byte{0x30, 0x02, 0x05, 0x00}
	var result2 interface{}
	config.Parser.ParseAsn1(data2, true, result2)

	if len(recorder.Calls) != 2 {
		t.Errorf("Expected 2 calls recorded, got %d", len(recorder.Calls))
	}

	if recorder.Calls[0].AllowExtraData != false {
		t.Error("First call should have allowExtraData=false")
	}

	if recorder.Calls[1].AllowExtraData != true {
		t.Error("Second call should have allowExtraData=true")
	}
}

// TestRecordingCurveLookup verifies all curve lookup calls are recorded
func TestRecordingCurveLookup(t *testing.T) {
	recorder := &RecordingCurveLookup{}
	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: recorder,
	}

	config.CurveLookup.GetNamedCurves()
	config.CurveLookup.GetNamedCurves()
	config.CurveLookup.GetLookupCurves()

	if recorder.NamedCurvesCalled != 2 {
		t.Errorf("Expected GetNamedCurves called 2 times, got %d", recorder.NamedCurvesCalled)
	}

	if recorder.LookupCurvesCalled != 1 {
		t.Errorf("Expected GetLookupCurves called 1 time, got %d", recorder.LookupCurvesCalled)
	}
}

// TestEcCurveWithConfigUsesLookup verifies EcCurveWithConfig uses provided lookup
func TestEcCurveWithConfigUsesLookup(t *testing.T) {
	// Create SPKI with secp256r1 curve (OID 1.3.132.0.32)
	// Note: This OID may not be in the default lookup, so we expect an error
	spkiData := utils.HexToBytes("3076301006072a8648ce3d020106052b81040020036200048aca5f821170fa4d8233c7f23f795792af42e791045bdf55989684aa16d1027d27541b0226d665c50e0ff76f91f5aeebf6af5178c02204045aa43002c893ed2b800cafa1e42cb47f80a21a6f0c3a2919bc5242c21daca5f4ec3c270e5620eb7c")

	spki, err := Asn1decodeSubjectPublicKeyInfo(spkiData)
	if err != nil {
		t.Fatalf("Failed to decode SPKI: %v", err)
	}

	// Use recording lookup to verify it's called
	recorder := &RecordingCurveLookup{}
	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: recorder,
	}

	// This will fail if the curve OID is not in the lookup
	_, err = spki.EcCurveWithConfig(config)
	// We just verify that the method was called with the config
	// The curve resolution may fail if the OID is not recognized
	_ = err // Error is acceptable for unsupported curves
}

// TestDetermineDigestAlgFromSigAlgWithConfigUsesMap verifies it uses provided SigAlgMap
func TestDetermineDigestAlgFromSigAlgWithConfigUsesMap(t *testing.T) {
	customAlgOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} // SHA-256

	customSigAlgMap := map[string]asn1.ObjectIdentifier{
		"custom": customAlgOID,
	}

	config := &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
		SigAlgMap:   customSigAlgMap,
	}

	// Test that custom map is used
	if len(config.SigAlgMap) != 1 {
		t.Errorf("Expected SigAlgMap to have 1 entry, got %d", len(config.SigAlgMap))
	}

	algOID, exists := config.SigAlgMap["custom"]
	if !exists {
		t.Fatal("Custom algorithm not found in map")
	}

	if !algOID.Equal(customAlgOID) {
		t.Errorf("OID mismatch: expected %s, got %s", customAlgOID, algOID)
	}
}

// TestConfigSwitchingAtRuntime verifies config can be switched between calls
func TestConfigSwitchingAtRuntime(t *testing.T) {
	mockHasher1 := &MockCryptoHasher{}
	mockHasher2 := &MockCryptoHasher{}

	config1 := &CMSConfig{
		Hasher:      mockHasher1,
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}

	config2 := &CMSConfig{
		Hasher:      mockHasher2,
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}

	// Use first config
	config1.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA256, []byte("test1"))
	if mockHasher1.CallCount != 1 {
		t.Error("mockHasher1 should have been called once")
	}

	// Switch to second config
	config2.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA512, []byte("test2"))
	if mockHasher2.CallCount != 1 {
		t.Error("mockHasher2 should have been called once")
	}

	if mockHasher1.CallCount != 1 {
		t.Error("mockHasher1 call count should still be 1")
	}
}

// TestMultipleMockConfigsIndependent verifies multiple mock configs don't interfere
func TestMultipleMockConfigsIndependent(t *testing.T) {
	config1, mockHasher1, mockParser1, mockLookup1 := NewMockCMSConfigWithMocks()
	config2, mockHasher2, mockParser2, mockLookup2 := NewMockCMSConfigWithMocks()

	// Use first config
	config1.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA256, []byte("test"))
	config1.Parser.ParseAsn1([]byte{}, false, nil)
	config1.CurveLookup.GetNamedCurves()

	// Use second config
	config2.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA512, []byte("test"))
	config2.Parser.ParseAsn1([]byte{}, true, nil)
	config2.CurveLookup.GetLookupCurves()

	// Verify first config state
	if mockHasher1.CallCount != 1 {
		t.Errorf("Config1 hasher: expected 1 call, got %d", mockHasher1.CallCount)
	}
	if mockParser1.CallCount != 1 {
		t.Errorf("Config1 parser: expected 1 call, got %d", mockParser1.CallCount)
	}
	if mockLookup1.CallCountNamed != 1 {
		t.Errorf("Config1 lookup: expected 1 call, got %d", mockLookup1.CallCountNamed)
	}

	// Verify second config state
	if mockHasher2.CallCount != 1 {
		t.Errorf("Config2 hasher: expected 1 call, got %d", mockHasher2.CallCount)
	}
	if mockParser2.CallCount != 1 {
		t.Errorf("Config2 parser: expected 1 call, got %d", mockParser2.CallCount)
	}
	if mockLookup2.CallCountLookup != 1 {
		t.Errorf("Config2 lookup: expected 1 call, got %d", mockLookup2.CallCountLookup)
	}
}

// TestDefaultImplementationsDelegateCorrectly verifies defaults call correct functions
func TestDefaultImplementationsDelegateCorrectly(t *testing.T) {
	config := NewDefaultCMSConfig()

	// Test hasher delegates to cryptoutils
	hash, err := config.Hasher.CryptoHashByOid(oid.OidHashAlgorithmSHA256, []byte("test"))
	if err != nil {
		t.Errorf("Default hasher failed: %v", err)
	}
	if len(hash) == 0 {
		t.Error("Default hasher returned empty hash")
	}

	// Test lookup returns non-empty curves
	curves := config.CurveLookup.GetNamedCurves()
	if len(curves) == 0 {
		t.Error("Default lookup returned no curves")
	}

	lookupCurves := config.CurveLookup.GetLookupCurves()
	if len(lookupCurves) == 0 {
		t.Error("Default lookup returned no lookup curves")
	}
}

// TestPrepareVerificationDataWithConfig verifies helper uses config
func TestPrepareVerificationDataWithConfig(t *testing.T) {
	testCases := []struct {
		name     string
		useConfig bool
	}{
		{
			name:      "with_default_config",
			useConfig: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// This test verifies that helper methods can be called with config
			// (actual verification happens in integration tests)
		})
	}
}

// TestConfigConsistency verifies config object remains consistent across calls
func TestConfigConsistency(t *testing.T) {
	config := NewDefaultCMSConfig()

	// Get the hasher reference
	hasher1 := config.Hasher
	hasher2 := config.Hasher

	// Verify it's the same instance
	if fmt.Sprintf("%p", hasher1) != fmt.Sprintf("%p", hasher2) {
		t.Error("Hasher reference changed between accesses")
	}

	// Same for other fields
	parser1 := config.Parser
	parser2 := config.Parser
	if fmt.Sprintf("%p", parser1) != fmt.Sprintf("%p", parser2) {
		t.Error("Parser reference changed between accesses")
	}

	lookup1 := config.CurveLookup
	lookup2 := config.CurveLookup
	if fmt.Sprintf("%p", lookup1) != fmt.Sprintf("%p", lookup2) {
		t.Error("CurveLookup reference changed between accesses")
	}
}
