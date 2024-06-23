package gmrtd

import (
	"encoding/asn1"
	"log"
)

// OIDs taken from:
//
// 9.2.1 PACEInfo
// 9.2.2 PACEDomainParameterInfo
// 9.2.3 PACE Object Identifier
// 9.2.4 ActiveAuthenticationInfo
// 9.2.5 ChipAuthenticationInfo
// 9.2.6 ChipAuthenticationPublicKeyInfo
// 9.2.7 Chip Authentication Object Identifier
// 9.2.8 TerminalAuthenticationInfo
// 9.2.9 Terminal Authentication Object Identifiers
// 9.2.10 EFDIRInfo

var (
	oidBsiDe                            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7}
	oidBsiDeAlgorithms                  = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1}
	oidBsiDeEcKeyType                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 2}
	oidBsiDeProtocols                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2}
	oidBsiDeProtocolsSmartcard          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2}
	oidPk                               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1}
	oidPkDh                             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 1}
	oidPkEcdh                           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 2}
	oidTa                               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2}
	oidTaRsa                            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1}
	oidTaRsaPssSha256                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 4}
	oidTaRsaPssSha512                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 6}
	oidTaEcdsa                          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2}
	oidTaEcdsaSha224                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 2}
	oidTaEcdsaSha256                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 3}
	oidTaEcdsaSha384                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 4}
	oidTaEcdsaSha512                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 5}
	oidCa                               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3}
	oidCaDh                             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1}
	oidCaDh3DesCbcCbc                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 1}
	oidCaDhAesCbcCmac128                = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 2}
	oidCaDhAesCbcCmac192                = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 3}
	oidCaDhAesCbcCmac256                = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 4}
	oidCaEcdh                           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2}
	oidCaEcdh3DesCbcCbc                 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 1}
	oidCaEcdhAesCbcCmac128              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 2}
	oidCaEcdhAesCbcCmac192              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 3}
	oidCaEcdhAesCbcCmac256              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 4}
	oidPace                             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4}
	oidPaceDhGm                         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1}
	oidPaceDhGm3DesCbcCbc               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1}
	oidPaceDhGmAesCbcCmac128            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2}
	oidPaceDhGmAesCbcCmac192            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 3}
	oidPaceDhGmAesCbcCmac256            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 4}
	oidPaceEcdhGm                       = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2}
	oidPaceEcdhGm3DesCbcCbc             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 1}
	oidPaceEcdhGmAesCbcCmac128          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2}
	oidPaceEcdhGmAesCbcCmac192          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 3}
	oidPaceEcdhGmAesCbcCmac256          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4}
	oidPaceDhIm                         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3}
	oidPaceDhIm3DesCbcCbc               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 1}
	oidPaceDhImAesCbcCmac128            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 2}
	oidPaceDhImAesCbcCmac192            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 3}
	oidPaceDhImAesCbcCmac256            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 4}
	oidPaceEcdhIm                       = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4}
	oidPaceEcdhIm3DesCbcCbc             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 1}
	oidPaceEcdhImAesCbcCmac128          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 2}
	oidPaceEcdhImAesCbcCmac192          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 3}
	oidPaceEcdhImAesCbcCmac256          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4}
	oidPaceEcdhCam                      = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6}
	oidPaceEcdhCamAesCbcCmac128         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 2}
	oidPaceEcdhCamAesCbcCmac192         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 3}
	oidPaceEcdhCamAesCbcCmac256         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 4}
	oidSecurityObject                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 3, 2, 1}
	oidPrimeField                       = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
	oidEcPublicKey                      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEcdsaWithSHA1                    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidEcdsaWithSHA224                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidEcdsaWithSHA256                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidEcdsaWithSHA384                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidEcdsaWithSHA512                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidRsaEncryption                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidMgf1                             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRsaSsaPss                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSha256WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSha384WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSha512WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSha224WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidSignedData                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEmailAddress                     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidContentType                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidHashAlgorithmMD5                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidHashAlgorithmSHA1                = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidIcao                             = asn1.ObjectIdentifier{1, 3, 27}
	oidIcaoMrtdSecurity                 = asn1.ObjectIdentifier{1, 3, 27, 1, 1}
	oidIcaoMrtdSecurityAaProtocolObject = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 5}
	oidEfDir                            = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 13}
	oidCommonName                       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber                     = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidCountryName                      = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocalityName                     = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidStateOrProvinceName              = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidOrganizationName                 = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnitName           = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidSubjectKeyIdentifier             = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidCeKeyUsage                       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidPrivateKeyUsagePeriod            = asn1.ObjectIdentifier{2, 5, 29, 16}
	oidSubjectAltName                   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidCeIssuerAltName                  = asn1.ObjectIdentifier{2, 5, 29, 18}
	oidCeCRLDistributionPoints          = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidCertificatePolicies              = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidAuthorityKeyIdentifier           = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidHashAlgorithmSHA256              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidHashAlgorithmSHA384              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidHashAlgorithmSHA512              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidHashAlgorithmSHA224              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidLdsSecurityObject                = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	oidDocumentTypeList                 = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 6, 2}
)

var oidLookup = map[string]string{
	oidBsiDe.String():                            "bsi-de",
	oidBsiDeAlgorithms.String():                  "algorithms",
	oidBsiDeEcKeyType.String():                   "keyType",
	oidBsiDeProtocols.String():                   "protocols",
	oidBsiDeProtocolsSmartcard.String():          "smartcards",
	oidPk.String():                               "id-PK",
	oidPkDh.String():                             "id-PK-DH",
	oidPkEcdh.String():                           "id-PK-ECDH",
	oidTa.String():                               "id-TA",
	oidTaRsa.String():                            "id-TA-RSA",
	oidTaRsaPssSha256.String():                   "id-TA-RSA-PSS-SHA-256",
	oidTaRsaPssSha512.String():                   "id-TA-RSA-PSS-SHA-512",
	oidTaEcdsa.String():                          "id-TA-ECDSA",
	oidTaEcdsaSha224.String():                    "id-TA-ECDSA-SHA-224",
	oidTaEcdsaSha256.String():                    "id-TA-ECDSA-SHA-256",
	oidTaEcdsaSha384.String():                    "id-TA-ECDSA-SHA-384",
	oidTaEcdsaSha512.String():                    "id-TA-ECDSA-SHA-512",
	oidCa.String():                               "id-CA",
	oidCaDh.String():                             "id-CA-DH",
	oidCaDh3DesCbcCbc.String():                   "id-CA-DH-3DES-CBC-CBC",
	oidCaDhAesCbcCmac128.String():                "id-CA-DH-AES-CBC-CMAC-128",
	oidCaDhAesCbcCmac192.String():                "id-CA-DH-AES-CBC-CMAC-192",
	oidCaDhAesCbcCmac256.String():                "id-CA-DH-AES-CBC-CMAC-256",
	oidCaEcdh.String():                           "id-CA-ECDH",
	oidCaEcdh3DesCbcCbc.String():                 "id-CA-ECDH-3DES-CBC-CBC",
	oidCaEcdhAesCbcCmac128.String():              "id-CA-ECDH-AES-CBC-CMAC-128",
	oidCaEcdhAesCbcCmac192.String():              "id-CA-ECDH-AES-CBC-CMAC-192",
	oidCaEcdhAesCbcCmac256.String():              "id-CA-ECDH-AES-CBC-CMAC-256",
	oidPace.String():                             "id-PACE",
	oidPaceDhGm.String():                         "id-PACE-DH-GM",
	oidPaceDhGm3DesCbcCbc.String():               "id-PACE-DH-GM-3DES-CBC-CBC",
	oidPaceDhGmAesCbcCmac128.String():            "id-PACE-DH-GM-AES-CBC-CMAC-128",
	oidPaceDhGmAesCbcCmac192.String():            "id-PACE-DH-GM-AES-CBC-CMAC-192",
	oidPaceDhGmAesCbcCmac256.String():            "id-PACE-DH-GM-AES-CBC-CMAC-256",
	oidPaceEcdhGm.String():                       "id-PACE-ECDH-GM",
	oidPaceEcdhGm3DesCbcCbc.String():             "id-PACE-ECDH-GM-3DES-CBC-CBC",
	oidPaceEcdhGmAesCbcCmac128.String():          "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
	oidPaceEcdhGmAesCbcCmac192.String():          "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
	oidPaceEcdhGmAesCbcCmac256.String():          "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
	oidPaceDhIm.String():                         "id-PACE-DH-IM",
	oidPaceDhIm3DesCbcCbc.String():               "id-PACE-DH-IM-3DES-CBC-CBC",
	oidPaceDhImAesCbcCmac128.String():            "id-PACE-DH-IM-AES-CBC-CMAC-128",
	oidPaceDhImAesCbcCmac192.String():            "id-PACE-DH-IM-AES-CBC-CMAC-192",
	oidPaceDhImAesCbcCmac256.String():            "id-PACE-DH-IM-AES-CBC-CMAC-256",
	oidPaceEcdhIm.String():                       "id-PACE-ECDH-IM",
	oidPaceEcdhIm3DesCbcCbc.String():             "id-PACE-ECDH-IM-3DES-CBC-CBC",
	oidPaceEcdhImAesCbcCmac128.String():          "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
	oidPaceEcdhImAesCbcCmac192.String():          "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
	oidPaceEcdhImAesCbcCmac256.String():          "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
	oidPaceEcdhCam.String():                      "id-PACE-ECDH-CAM",
	oidPaceEcdhCamAesCbcCmac128.String():         "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
	oidPaceEcdhCamAesCbcCmac192.String():         "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
	oidPaceEcdhCamAesCbcCmac256.String():         "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",
	oidSecurityObject.String():                   "id-SecurityObject",
	oidPrimeField.String():                       "prime-field",
	oidEcPublicKey.String():                      "id-ecPublicKey",
	oidEcdsaWithSHA1.String():                    "ecdsa-with-SHA1",
	oidEcdsaWithSHA224.String():                  "ecdsa-with-SHA224",
	oidEcdsaWithSHA256.String():                  "ecdsa-with-SHA256",
	oidEcdsaWithSHA384.String():                  "ecdsa-with-SHA384",
	oidEcdsaWithSHA512.String():                  "ecdsa-with-SHA512",
	oidRsaEncryption.String():                    "rsaEncryption",
	oidMgf1.String():                             "id-mgf1",
	oidRsaSsaPss.String():                        "id-RSASSA-PSS",
	oidSha256WithRSAEncryption.String():          "sha256WithRSAEncryption",
	oidSha384WithRSAEncryption.String():          "sha384WithRSAEncryption",
	oidSha512WithRSAEncryption.String():          "sha512WithRSAEncryption",
	oidSha224WithRSAEncryption.String():          "sha224WithRSAEncryption",
	oidSignedData.String():                       "id-signedData",
	oidEmailAddress.String():                     "emailAddress",
	oidContentType.String():                      "contentType",
	oidMessageDigest.String():                    "id-messageDigest",
	oidSigningTime.String():                      "signing-time",
	oidHashAlgorithmMD5.String():                 "md5",
	oidHashAlgorithmSHA1.String():                "sha1",
	oidIcao.String():                             "id-icao",
	oidIcaoMrtdSecurity.String():                 "id-icao-mrtd-security",
	oidIcaoMrtdSecurityAaProtocolObject.String(): "id-icao-mrtd-security-aaProtocolObject",
	oidEfDir.String():                            "id-EFDIR",
	oidCommonName.String():                       "commonName",
	oidSerialNumber.String():                     "serialNumber",
	oidCountryName.String():                      "countryName",
	oidLocalityName.String():                     "localityName",
	oidStateOrProvinceName.String():              "stateOrProvinceName",
	oidOrganizationName.String():                 "organizationName",
	oidOrganizationalUnitName.String():           "organizationalUnitName",
	oidSubjectKeyIdentifier.String():             "subjectKeyIdentifier",
	oidCeKeyUsage.String():                       "id-ce-keyUsage",
	oidPrivateKeyUsagePeriod.String():            "privateKeyUsagePeriod",
	oidSubjectAltName.String():                   "subjectAltName",
	oidCeIssuerAltName.String():                  "id-ce-issuerAltName",
	oidCeCRLDistributionPoints.String():          "id-ce-cRLDistributionPoints",
	oidCertificatePolicies.String():              "certificatePolicies",
	oidAuthorityKeyIdentifier.String():           "authorityKeyIdentifier",
	oidHashAlgorithmSHA256.String():              "sha256",
	oidHashAlgorithmSHA384.String():              "sha384",
	oidHashAlgorithmSHA512.String():              "sha512",
	oidHashAlgorithmSHA224.String():              "sha224",
	oidLdsSecurityObject.String():                "ldsSecurityObject",
	oidDocumentTypeList.String():                 "documentTypeList",
}

// determines if 'oid' starts with 'prefix' (but not equal to - i.e. oid != prefix)
func oidHasPrefix(oid asn1.ObjectIdentifier, prefixOid asn1.ObjectIdentifier) bool {
	// oid must be longer than prefix
	if len(oid) <= len(prefixOid) {
		return false
	}

	return prefixOid.Equal(oid[:len(prefixOid)])
}

// gets the raw OID bytes (without the leading tag/length - 0x06,<len>)
func oidBytes(oid asn1.ObjectIdentifier) []byte {
	asn1bytes, err := asn1.Marshal(oid)
	if err != nil {
		log.Panicf("Unable to encode OID []int (%s)", err.Error())
	}

	return TlvDecode(asn1bytes).GetNode(0x06).GetValue()

}

// decodes the raw OID bytes (excluding the tag/length)
func DecodeAsn1objectId(data []byte) (oid asn1.ObjectIdentifier) {
	var dataWithTag []byte

	// wrap data with ASN1 OID tag (0x06)
	dataWithTag = append(dataWithTag, 0x06)
	dataWithTag = append(dataWithTag, byte(len(data)))
	dataWithTag = append(dataWithTag, data...)

	// attempt to parse OID
	if rest, err := asn1.Unmarshal(dataWithTag, &oid); len(rest) > 0 || err != nil {
		log.Panicf("Error parsing ASN1 OID")
	}

	return oid
}
