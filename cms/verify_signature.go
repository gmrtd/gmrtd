package cms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

var (
	asn1DecodeSubjectPublicKeyInfoFn = Asn1decodeSubjectPublicKeyInfo
	cryptoHashOidToAlgFn             = cryptoutils.CryptoHashOidToAlg
	ecdsaVerifyASN1Fn                = ecdsa.VerifyASN1
	rsaVerifyPKCS1v15Fn              = rsa.VerifyPKCS1v15
	rsaVerifyPSSFn                   = rsa.VerifyPSS
	getAlternativeCurvesFn           = getAlternativeCurves
	decodeECDSAPublicKeyFn           = decodeECDSAPublicKey
	decodeRSAPublicKeyFn             = decodeRSAPublicKey
)

// VerifySignature verifies a signature using the supplied public key info and signature algorithm.
func VerifySignature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest []byte, sigAlg asn1.ObjectIdentifier, sig []byte) error {
	slog.Debug(
		"VerifySignature",
		"pubKeyInfo", utils.BytesToHex(pubKeyInfo),
		"digestAlg", digestAlg.String(),
		"digest", utils.BytesToHex(digest),
		"sigAlg", sigAlg.String(),
		"sig", utils.BytesToHex(sig),
	)

	switch {
	case isECDSASignatureAlgorithm(sigAlg):
		return verifyECDSASignature(pubKeyInfo, digest, sig)

	case isRSAPKCS1SignatureAlgorithm(sigAlg):
		return verifyRSAPKCS1Signature(pubKeyInfo, digestAlg, digest, sig)

	case isRSAPSSSignatureAlgorithm(sigAlg):
		return verifyRSAPSSSignature(pubKeyInfo, digestAlg, digest, sig)

	default:
		return fmt.Errorf("[VerifySignature] Unsupported sigAlg: %s", sigAlg.String())
	}
}

func verifyECDSASignature(pubKeyInfo, digest, sig []byte) error {
	pub, err := decodeECDSAPublicKeyFn(pubKeyInfo)
	if err != nil {
		return fmt.Errorf("[verifyECDSASignature] decodeECDSAPublicKeyFn error: %w", err)
	}

	r, s, err := parseECDSASignature(sig)
	if err != nil {
		return fmt.Errorf("[verifyECDSASignature] parseECDSASignature error: %w", err)
	}

	check := evaluateECDSASignatureRange(pub.Curve, r, s)
	logECDSARangeCheck(check, r, s)

	tmpDigest := truncateHashForEcdsa(digest, pub.Curve)
	validSig := ecdsaVerifyASN1Fn(pub, tmpDigest, sig)
	slog.Debug("VerifySignature", "validSig", validSig)

	if validSig {
		return nil
	}

	logBadECDSASignature(pub, tmpDigest, sig)

	if check.rOutOfRange || check.sOutOfRange {
		if tryAlternativeECDSACurves(pub, digest, sig, r, s, check.curveName) {
			return nil
		}
	}

	return fmt.Errorf("[verifyECDSASignature] Invalid ECDSA Signature")
}

func verifyRSAPKCS1Signature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest, sig []byte) error {
	rsaPubKey, err := decodeRSAPublicKeyFn(pubKeyInfo)
	if err != nil {
		return fmt.Errorf("[verifyRSAPKCS1Signature] decodeRSAPublicKey error: %w", err)
	}

	hashAlg, err := cryptoHashOidToAlgFn(digestAlg)
	if err != nil {
		return fmt.Errorf("[verifyRSAPKCS1Signature] cryptoHashOidToAlg error: %w", err)
	}

	if err := rsaVerifyPKCS1v15Fn(rsaPubKey, hashAlg, digest, sig); err != nil { // NOSONAR
		slog.Debug(
			"VerifySignature - RSA PKCS#1 v1.5 signature verification FAILED",
			"digestAlg", digestAlg.String(),
			"digest", utils.BytesToHex(digest),
			"error", err,
		)
		return fmt.Errorf("[verifyRSAPKCS1Signature] rsaVerifyPKCS1v15 err: %w", err)
	}

	return nil
}

func verifyRSAPSSSignature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest, sig []byte) error {
	rsaPubKey, err := decodeRSAPublicKeyFn(pubKeyInfo)
	if err != nil {
		return fmt.Errorf("[verifyRSAPSSSignature] decodeRSAPublicKey error: %w", err)
	}

	hashAlg, err := cryptoHashOidToAlgFn(digestAlg)
	if err != nil {
		return fmt.Errorf("[verifyRSAPSSSignature] cryptoHashOidToAlg error: %w", err)
	}

	if err := rsaVerifyPSSFn(rsaPubKey, hashAlg, digest, sig, nil); err != nil {
		return fmt.Errorf("[verifyRSAPSSSignature] rsaVerifyPSS error: %w", err)
	}

	return nil
}

func decodeECDSAPublicKey(pubKeyInfo []byte) (*ecdsa.PublicKey, error) {
	subPubKeyInfo, err := asn1DecodeSubjectPublicKeyInfoFn(pubKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("[decodeECDSAPublicKey] asn1DecodeSubjectPublicKeyInfoFn error: %w", err)
	}

	// NB following code (EcCurveAndPubKey) will also try alternative curves, if specified curve is not valid for the public-key
	ecCurve, ecPoint, err := subPubKeyInfo.EcCurveAndPubKey(true)
	if err != nil {
		return nil, fmt.Errorf("[decodeECDSAPublicKey] EcCurveAndPubKey error: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: *ecCurve,
		X:     ecPoint.X,
		Y:     ecPoint.Y,
	}, nil
}

func decodeRSAPublicKey(pubKeyInfo []byte) (*rsa.PublicKey, error) {
	subPubKeyInfo, err := asn1DecodeSubjectPublicKeyInfoFn(pubKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("[decodeRSAPublicKey] asn1DecodeSubjectPublicKeyInfoFn error: %w", err)
	}

	pubKey, err := subPubKeyInfo.RsaPubKey()
	if err != nil {
		return nil, fmt.Errorf("[decodeRSAPublicKey] RsaPubKey error: %s", err)
	}

	return &rsa.PublicKey{
		N: pubKey.N,
		E: pubKey.E,
	}, nil
}

type ecdsaRangeCheck struct {
	curveName   string
	curveOrder  *big.Int
	orderBits   int
	rOutOfRange bool
	sOutOfRange bool
}

func evaluateECDSASignatureRange(curve elliptic.Curve, r, s *big.Int) ecdsaRangeCheck {
	curveOrder := curve.Params().N

	return ecdsaRangeCheck{
		curveName:   getCurveName(curve),
		curveOrder:  curveOrder,
		orderBits:   curveOrder.BitLen(),
		rOutOfRange: r.Sign() <= 0 || r.Cmp(curveOrder) >= 0,
		sOutOfRange: s.Sign() <= 0 || s.Cmp(curveOrder) >= 0,
	}
}

func tryAlternativeECDSACurves(pub *ecdsa.PublicKey, digest, sig []byte, r, s *big.Int, specifiedCurveName string) bool {
	slog.Warn("VerifySignature attempting curve fallback due to out-of-range signature values")

	for _, altCurve := range getAlternativeCurvesFn(pub.Curve) {
		altCurveName := getCurveName(altCurve)
		slog.Info("VerifySignature trying alternative curve", "curve", altCurveName)

		altCheck := evaluateECDSASignatureRange(altCurve, r, s)
		if altCheck.rOutOfRange || altCheck.sOutOfRange {
			slog.Info(
				"VerifySignature signature values still out of range for alternative curve",
				"curve", altCurveName,
				"rOutOfRange", altCheck.rOutOfRange,
				"sOutOfRange", altCheck.sOutOfRange,
			)
			continue
		}

		altPub := &ecdsa.PublicKey{
			Curve: altCurve,
			X:     pub.X,
			Y:     pub.Y,
		}
		altDigest := truncateHashForEcdsa(digest, altCurve)

		if ecdsaVerifyASN1Fn(altPub, altDigest, sig) {
			slog.Warn(
				"VerifySignature signature verified with ALTERNATIVE curve (possible passport issuing bug)",
				"specifiedCurve", specifiedCurveName,
				"workingCurve", altCurveName,
			)
			return true
		}
	}

	slog.Warn("VerifySignature curve fallback failed - no alternative curves worked")
	return false
}

func logECDSARangeCheck(check ecdsaRangeCheck, r, s *big.Int) {
	slog.Debug(
		"VerifySignature ECDSA",
		"curve", check.curveName,
		"curveOrderBits", check.orderBits,
		"rOutOfRange", check.rOutOfRange,
		"sOutOfRange", check.sOutOfRange,
	)

	if check.rOutOfRange || check.sOutOfRange {
		slog.Warn(
			"VerifySignature ECDSA signature values out of range for curve",
			"curve", check.curveName,
			"R", utils.BytesToHex(r.Bytes()),
			"S", utils.BytesToHex(s.Bytes()),
			"curveOrder", utils.BytesToHex(check.curveOrder.Bytes()),
			"rOutOfRange", check.rOutOfRange,
			"sOutOfRange", check.sOutOfRange,
		)
	}
}

func logBadECDSASignature(pub *ecdsa.PublicKey, digest, sig []byte) {
	var pubBytesX, pubBytesY []byte

	if pub.X != nil {
		pubBytesX = pub.X.Bytes()
	}

	if pub.Y != nil {
		pubBytesY = pub.Y.Bytes()
	}

	slog.Info(
		"VerifySignature (bad ECDSA signature)",
		"pub.X", utils.BytesToHex(pubBytesX),
		"pub.Y", utils.BytesToHex(pubBytesY),
		"digest", utils.BytesToHex(digest),
		"signature", utils.BytesToHex(sig),
	)
}

func isECDSASignatureAlgorithm(sigAlg asn1.ObjectIdentifier) bool {
	return sigAlg.Equal(oid.OidEcdsaWithSHA1) ||
		sigAlg.Equal(oid.OidEcdsaWithSHA224) ||
		sigAlg.Equal(oid.OidEcdsaWithSHA256) ||
		sigAlg.Equal(oid.OidEcdsaWithSHA384) ||
		sigAlg.Equal(oid.OidEcdsaWithSHA512)
}

func isRSAPKCS1SignatureAlgorithm(sigAlg asn1.ObjectIdentifier) bool {
	return sigAlg.Equal(oid.OidRsaEncryption) ||
		sigAlg.Equal(oid.OidSha1WithRsaEncryption) ||
		sigAlg.Equal(oid.OidSha224WithRSAEncryption) ||
		sigAlg.Equal(oid.OidSha256WithRSAEncryption) ||
		sigAlg.Equal(oid.OidSha384WithRSAEncryption) ||
		sigAlg.Equal(oid.OidSha512WithRSAEncryption)
}

func isRSAPSSSignatureAlgorithm(sigAlg asn1.ObjectIdentifier) bool {
	return sigAlg.Equal(oid.OidRsaSsaPss)
}

// TODO - not sure whether this is even achieving anything?
func truncateHashForEcdsa(hash []byte, curve elliptic.Curve) []byte {
	orderBits := curve.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8

	if len(hash) > orderBytes {
		return hash[:orderBytes]
	}

	return hash
}

func parseECDSASignature(sig []byte) (r, s *big.Int, err error) {
	var ecdsaSig struct {
		R, S *big.Int
	}

	rest, err := asn1.Unmarshal(sig, &ecdsaSig)
	if err != nil {
		return nil, nil, fmt.Errorf("[parseECDSASignature] asn1.Unmarshall error: %w", err)
	}
	if len(rest) != 0 {
		return nil, nil, fmt.Errorf("[parseECDSASignature] trailing bytes (len:%d)", len(rest))
	}

	return ecdsaSig.R, ecdsaSig.S, nil
}
