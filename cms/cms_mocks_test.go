package cms

import (
	"crypto/elliptic"
	"encoding/asn1"

	"github.com/gmrtd/gmrtd/utils"
)

// MockCryptoHasher is a mock implementation of CryptoHasher for testing
type MockCryptoHasher struct {
	HashFunc  func(oid asn1.ObjectIdentifier, data []byte) ([]byte, error)
	CallCount int
	LastOID   asn1.ObjectIdentifier
	LastData  []byte
}

func (m *MockCryptoHasher) CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	m.CallCount++
	m.LastOID = oid
	m.LastData = data
	if m.HashFunc != nil {
		return m.HashFunc(oid, data)
	}
	// Default: return empty hash
	return []byte{}, nil
}

// MockAsn1Parser is a mock implementation of Asn1Parser for testing
type MockAsn1Parser struct {
	ParseFunc func(data []byte, allowExtraData bool, v interface{}) error
	CallCount int
	LastData  []byte
}

func (m *MockAsn1Parser) ParseAsn1(data []byte, allowExtraData bool, v interface{}) error {
	m.CallCount++
	m.LastData = data
	if m.ParseFunc != nil {
		return m.ParseFunc(data, allowExtraData, v)
	}
	return nil
}

// MockCurveLookup is a mock implementation of CurveLookup for testing
type MockCurveLookup struct {
	NamedCurves    []EcNamedCurve
	LookupCurves   []elliptic.Curve
	CallCountNamed int
	CallCountLookup int
}

func (m *MockCurveLookup) GetNamedCurves() []EcNamedCurve {
	m.CallCountNamed++
	return m.NamedCurves
}

func (m *MockCurveLookup) GetLookupCurves() []elliptic.Curve {
	m.CallCountLookup++
	return m.LookupCurves
}

// NewMockCMSConfigWithDefaults creates a CMSConfig with default implementations
func NewMockCMSConfigWithDefaults() *CMSConfig {
	return &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
	}
}

// NewMockCMSConfigWithMocks creates a CMSConfig with mock implementations
func NewMockCMSConfigWithMocks() (*CMSConfig, *MockCryptoHasher, *MockAsn1Parser, *MockCurveLookup) {
	mockHasher := &MockCryptoHasher{}
	mockParser := &MockAsn1Parser{}
	
	// Get curves from default lookup
	defaultLookup := DefaultCurveLookup{}
	mockLookup := &MockCurveLookup{
		NamedCurves:  defaultLookup.GetNamedCurves(),
		LookupCurves: defaultLookup.GetLookupCurves(),
	}

	config := &CMSConfig{
		Hasher:      mockHasher,
		Parser:      mockParser,
		CurveLookup: mockLookup,
	}

	return config, mockHasher, mockParser, mockLookup
}

// ErrorHasher returns a hasher that always fails
func NewErrorHasher(err error) CryptoHasher {
	return &mockErrorHasher{err: err}
}

type mockErrorHasher struct {
	err error
}

func (m *mockErrorHasher) CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	return nil, m.err
}

// ErrorParser returns a parser that always fails
func NewErrorParser(err error) Asn1Parser {
	return &mockErrorParser{err: err}
}

type mockErrorParser struct {
	err error
}

func (m *mockErrorParser) ParseAsn1(data []byte, allowExtraData bool, v interface{}) error {
	return m.err
}

// EmptyCurveLookup returns a lookup with no curves
func NewEmptyCurveLookup() CurveLookup {
	return &emptyCurveLookup{}
}

type emptyCurveLookup struct{}

func (e *emptyCurveLookup) GetNamedCurves() []EcNamedCurve {
	return []EcNamedCurve{}
}

func (e *emptyCurveLookup) GetLookupCurves() []elliptic.Curve {
	return []elliptic.Curve{}
}

// CustomSigAlgMapConfig creates config with custom signature algorithm mapping
func NewConfigWithCustomSigAlgMap(sigAlgMap map[string]asn1.ObjectIdentifier) *CMSConfig {
	return &CMSConfig{
		Hasher:      &DefaultCryptoHasher{},
		Parser:      &DefaultAsn1Parser{},
		CurveLookup: &DefaultCurveLookup{},
		SigAlgMap:   sigAlgMap,
	}
}

// RecordingCryptoHasher records all hash calls
type RecordingCryptoHasher struct {
	Calls []struct {
		OID  asn1.ObjectIdentifier
		Data []byte
	}
}

func (r *RecordingCryptoHasher) CryptoHashByOid(oid asn1.ObjectIdentifier, data []byte) ([]byte, error) {
	r.Calls = append(r.Calls, struct {
		OID  asn1.ObjectIdentifier
		Data []byte
	}{oid, data})
	return utils.HexToBytes("00"), nil // Return minimal hash
}

// RecordingAsn1Parser records all parse calls
type RecordingAsn1Parser struct {
	Calls []struct {
		Data          []byte
		AllowExtraData bool
	}
}

func (r *RecordingAsn1Parser) ParseAsn1(data []byte, allowExtraData bool, v interface{}) error {
	r.Calls = append(r.Calls, struct {
		Data          []byte
		AllowExtraData bool
	}{data, allowExtraData})
	// Delegate to default parser for actual parsing
	return DefaultAsn1Parser{}.ParseAsn1(data, allowExtraData, v)
}

// RecordingCurveLookup records all curve lookup calls
type RecordingCurveLookup struct {
	NamedCurvesCalled  int
	LookupCurvesCalled int
}

func (r *RecordingCurveLookup) GetNamedCurves() []EcNamedCurve {
	r.NamedCurvesCalled++
	defaultLookup := DefaultCurveLookup{}
	return defaultLookup.GetNamedCurves()
}

func (r *RecordingCurveLookup) GetLookupCurves() []elliptic.Curve {
	r.LookupCurvesCalled++
	defaultLookup := DefaultCurveLookup{}
	return defaultLookup.GetLookupCurves()
}
