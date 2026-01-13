package cms

import (
	"crypto"
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

func VerifySignature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest []byte, sigAlg asn1.ObjectIdentifier, sig []byte) (err error) {
	slog.Debug("VerifySignature", "pubKeyInfo", utils.BytesToHex(pubKeyInfo), "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest), "sigAlg", sigAlg.String(), "sig", utils.BytesToHex(sig))

	switch sigAlg.String() {
	/*
	* ECDSA
	 */
	case
		oid.OidEcdsaWithSHA1.String(),
		oid.OidEcdsaWithSHA224.String(),
		oid.OidEcdsaWithSHA256.String(),
		oid.OidEcdsaWithSHA384.String(),
		oid.OidEcdsaWithSHA512.String():
		{
			var pub *ecdsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)

				var ecCurve *elliptic.Curve
				var ecPoint *cryptoutils.EcPoint
				ecCurve, ecPoint, err = subPubKeyInfo.EcCurveAndPubKey()
				if err != nil {
					return fmt.Errorf("[VerifySignature] EcCurveAndPubKey error: %w", err)
				}

				if ecPoint == nil || ecPoint.X == nil || ecPoint.Y == nil {
					return fmt.Errorf("[VerifySignature] Invalid public key point")
				}

				pub = &ecdsa.PublicKey{Curve: *ecCurve, X: ecPoint.X, Y: ecPoint.Y}
			}

			// Parse signature to extract R and S values for validation
			r, s, err := parseEcdsaSignature(sig)
			if err != nil {
				return fmt.Errorf("[VerifySignature] Failed to parse ECDSA signature: %w", err)
			}

			// Get curve information for logging
			curveName := getCurveName(pub.Curve)
			curveOrder := pub.Curve.Params().N
			curveOrderBits := curveOrder.BitLen()

			// Check if R and S are within the curve's order
			rOutOfRange := r.Cmp(curveOrder) >= 0 || r.Sign() <= 0
			sOutOfRange := s.Cmp(curveOrder) >= 0 || s.Sign() <= 0

			// Enhanced logging
			slog.Info("VerifySignature ECDSA",
				"curve", curveName,
				"curveOrderBits", curveOrderBits,
				"rOutOfRange", rOutOfRange,
				"sOutOfRange", sOutOfRange)

			if rOutOfRange || sOutOfRange {
				slog.Warn("VerifySignature ECDSA signature values out of range for curve",
					"curve", curveName,
					"R", utils.BytesToHex(r.Bytes()),
					"S", utils.BytesToHex(s.Bytes()),
					"curveOrder", utils.BytesToHex(curveOrder.Bytes()),
					"rOutOfRange", rOutOfRange,
					"sOutOfRange", sOutOfRange)
			}

			// VerifyASN1: works with non-nist curves (i.e. brainpool) via legacy code (hopefully this doesn't change)
			tmpDigest := truncateHashForEcdsa(digest, pub.Curve)
			validSig := ecdsa.VerifyASN1(pub, tmpDigest, sig)
			slog.Debug("VerifySignature", "validSig", validSig)

			if !validSig {
				// Log signature verification failure
				if pub.X != nil && pub.Y != nil {
					slog.Info("VerifySignature (bad ECDSA signature)", "pub.X", utils.BytesToHex(pub.X.Bytes()), "pub.Y", utils.BytesToHex(pub.Y.Bytes()), "digest", utils.BytesToHex(tmpDigest), "signature", utils.BytesToHex(sig))
				} else {
					slog.Info("VerifySignature (bad ECDSA signature)", "digest", utils.BytesToHex(tmpDigest), "signature", utils.BytesToHex(sig))
				}

				// If signature failed and R/S are out of range, try alternative curves
				if rOutOfRange || sOutOfRange {
					slog.Warn("VerifySignature attempting curve fallback due to out-of-range signature values")

					alternatives := getAlternativeCurves(pub.Curve)
					for _, altCurve := range alternatives {
						altCurveName := getCurveName(altCurve)
						slog.Info("VerifySignature trying alternative curve", "curve", altCurveName)

						// Check if R and S are within the alternative curve's order
						altCurveOrder := altCurve.Params().N
						altROutOfRange := r.Cmp(altCurveOrder) >= 0 || r.Sign() <= 0
						altSOutOfRange := s.Cmp(altCurveOrder) >= 0 || s.Sign() <= 0

						if altROutOfRange || altSOutOfRange {
							slog.Info("VerifySignature signature values still out of range for alternative curve",
								"curve", altCurveName,
								"rOutOfRange", altROutOfRange,
								"sOutOfRange", altSOutOfRange)
							continue
						}

						// Try verification with alternative curve
						altPub := &ecdsa.PublicKey{Curve: altCurve, X: pub.X, Y: pub.Y}
						altDigest := truncateHashForEcdsa(digest, altCurve)
						altValidSig := ecdsa.VerifyASN1(altPub, altDigest, sig)

						if altValidSig {
							slog.Warn("VerifySignature signature verified with ALTERNATIVE curve (possible passport issuing bug)",
								"specifiedCurve", curveName,
								"workingCurve", altCurveName)
							return nil
						}
					}

					slog.Warn("VerifySignature curve fallback failed - no alternative curves worked")
				}

				return fmt.Errorf("[VerifySignature] Invalid ECDSA signature")
			}

			return nil
		}
	/*
	* RSA-Encryption (PKCS#1 v1.5)
	 */
	case
		oid.OidRsaEncryption.String(),
		oid.OidSha1WithRsaEncryption.String(),
		oid.OidSha224WithRSAEncryption.String(),
		oid.OidSha256WithRSAEncryption.String(),
		oid.OidSha384WithRSAEncryption.String(),
		oid.OidSha512WithRSAEncryption.String():
		{
			var pubKey *cryptoutils.RsaPublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				pubKey = subPubKeyInfo.RsaPubKey()
			}

			// Convert to crypto/rsa format
			rsaPubKey := &rsa.PublicKey{N: pubKey.N, E: pubKey.E}

			// Get the hash algorithm
			var hashAlg crypto.Hash
			hashAlg, err = cryptoutils.CryptoHashOidToAlg(digestAlg)
			if err != nil {
				return fmt.Errorf("[VerifySignature] CryptoHashOidToAlg error: %w", err)
			}

			// Use proper PKCS#1 v1.5 verification
			// This correctly validates the DigestInfo structure and padding format
			// Note: suppress secure mode and padding scheme warning in sonar
			//		 - this is required for RSA
			err = rsa.VerifyPKCS1v15(rsaPubKey, hashAlg, digest, sig) // NOSONAR
			if err != nil {
				slog.Debug("VerifySignature - RSA PKCS#1 v1.5 signature verification FAILED", "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest), "sigAlg", sigAlg.String(), "error", err)
				return fmt.Errorf("[VerifySignature] Invalid RSA PKCS#1 v1.5 signature: %w", err)
			}

			return nil
		}
	/*
	* RSA-PSS
	 */
	case oid.OidRsaSsaPss.String():
		{
			var rsaPubKey *rsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				var pubKey *cryptoutils.RsaPublicKey = subPubKeyInfo.RsaPubKey()
				rsaPubKey = &rsa.PublicKey{N: pubKey.N, E: pubKey.E}
			}

			var hashAlg crypto.Hash
			hashAlg, err = cryptoutils.CryptoHashOidToAlg(digestAlg)
			if err != nil {
				return fmt.Errorf("[VerifySignature] CryptoHashOidToAlg error: %w", err)
			}

			err = rsa.VerifyPSS(rsaPubKey, hashAlg, digest, sig, nil)
			if err != nil {
				return fmt.Errorf("[VerifySignature] Invalid PSS signature: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("[VerifySignature] signature-algorithm not supported: %s", sigAlg.String())
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

// parseEcdsaSignature parses an ASN.1 encoded ECDSA signature and extracts R and S values
func parseEcdsaSignature(sig []byte) (r, s *big.Int, err error) {
	var ecdsaSig struct {
		R, S *big.Int
	}

	_, err = asn1.Unmarshal(sig, &ecdsaSig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	return ecdsaSig.R, ecdsaSig.S, nil
}
