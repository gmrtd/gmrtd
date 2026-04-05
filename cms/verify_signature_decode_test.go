package cms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"testing"

	"github.com/gmrtd/gmrtd/oid"
)

// Test that obviously malformed ECDSA SubjectPublicKeyInfo fails
func TestDecodeECDSAPublicKeyInvalidDER(t *testing.T) {
	_, err := decodeECDSAPublicKey([]byte{0x30, 0x03, 0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error")
	}
}

// Test that a structurally valid SPKI with an empty EC point fails
func TestDecodeECDSAPublicKeyEmptyPoint(t *testing.T) {
	keyDER := buildECPublicKeyDERWithRawPoint(t, oid.OidPrime256v1, nil)

	_, err := decodeECDSAPublicKey(keyDER)
	if err == nil {
		t.Fatal("expected error")
	}
}

// Passing a non-RSA SPKI to decodeRSAPublicKey should fail.
func TestDecodeRSAPublicKey_WithECDSASPKI(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	keyDER := buildECPublicKeyDER(t, &priv.PublicKey, oid.OidPrime256v1)

	_, err = decodeRSAPublicKey(keyDER)
	if err == nil {
		t.Fatal("expected error")
	}
}

// Malformed DER for RSA decode should fail.
func TestDecodeRSAPublicKey_InvalidDER(t *testing.T) {
	_, err := decodeRSAPublicKey([]byte{0x30, 0x03, 0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error")
	}
}

func buildECPublicKeyDER(t *testing.T, pub *ecdsa.PublicKey, curveOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	rawPoint := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	return buildECPublicKeyDERWithRawPoint(t, curveOID, rawPoint)
}

func buildECPublicKeyDERWithRawPoint(t *testing.T, curveOID asn1.ObjectIdentifier, rawPoint []byte) []byte {
	t.Helper()

	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}

	type subjectPublicKeyInfo struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}

	algIDBytes, err := asn1.Marshal(algorithmIdentifier{
		Algorithm:  oid.OidEcPublicKey,
		Parameters: curveOID,
	})
	if err != nil {
		t.Fatalf("failed to marshal algorithm identifier: %v", err)
	}

	spki := subjectPublicKeyInfo{
		Algorithm: asn1.RawValue{FullBytes: algIDBytes},
		PublicKey: asn1.BitString{
			Bytes:     rawPoint,
			BitLength: len(rawPoint) * 8,
		},
	}

	keyDER, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("failed to marshal SubjectPublicKeyInfo: %v", err)
	}

	return keyDER
}

func TestDecodeRSAPublicKeyBadOid(t *testing.T) {
	orig := asn1DecodeSubjectPublicKeyInfoFn
	defer func() {
		asn1DecodeSubjectPublicKeyInfoFn = orig
	}()

	asn1DecodeSubjectPublicKeyInfoFn = func([]byte) (SubjectPublicKeyInfo, error) {
		return SubjectPublicKeyInfo{Algorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}}, nil
	}

	_, err := decodeRSAPublicKey([]byte("dummy"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestDecodeRSAPublicKeyBadKeyData(t *testing.T) {
	orig := asn1DecodeSubjectPublicKeyInfoFn
	defer func() {
		asn1DecodeSubjectPublicKeyInfoFn = orig
	}()

	asn1DecodeSubjectPublicKeyInfoFn = func([]byte) (SubjectPublicKeyInfo, error) {
		return SubjectPublicKeyInfo{Algorithm: AlgorithmIdentifier{Algorithm: oid.OidRsaEncryption}}, nil
	}

	_, err := decodeRSAPublicKey([]byte("dummy"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
