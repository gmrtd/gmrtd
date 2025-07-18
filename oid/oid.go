// Package oid provides utilities relating to ASN.1 'Object Identifiers' (OIDs).
package oid

import (
	"encoding/asn1"
	"fmt"
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
	OidBsiDe                            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7}
	OidBsiDeAlgorithms                  = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1}
	OidBsiDeEcKeyType                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 2}
	OidBsiDeProtocols                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2}
	OidBsiDeProtocolsSmartcard          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2}
	OidPk                               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1}
	OidPkDh                             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 1}
	OidPkEcdh                           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 1, 2}
	OidTa                               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2}
	OidTaRsa                            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1}
	OidTaRsaPssSha256                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 4}
	OidTaRsaPssSha512                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 1, 6}
	OidTaEcdsa                          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2}
	OidTaEcdsaSha224                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 2}
	OidTaEcdsaSha256                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 3}
	OidTaEcdsaSha384                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 4}
	OidTaEcdsaSha512                    = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 2, 2, 5}
	OidCa                               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3}
	OidCaDh                             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1}
	OidCaDh3DesCbcCbc                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 1}
	OidCaDhAesCbcCmac128                = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 2}
	OidCaDhAesCbcCmac192                = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 3}
	OidCaDhAesCbcCmac256                = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 1, 4}
	OidCaEcdh                           = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2}
	OidCaEcdh3DesCbcCbc                 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 1}
	OidCaEcdhAesCbcCmac128              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 2}
	OidCaEcdhAesCbcCmac192              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 3}
	OidCaEcdhAesCbcCmac256              = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 3, 2, 4}
	OidPace                             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4}
	OidPaceDhGm                         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1}
	OidPaceDhGm3DesCbcCbc               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 1}
	OidPaceDhGmAesCbcCmac128            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 2}
	OidPaceDhGmAesCbcCmac192            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 3}
	OidPaceDhGmAesCbcCmac256            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 1, 4}
	OidPaceEcdhGm                       = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2}
	OidPaceEcdhGm3DesCbcCbc             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 1}
	OidPaceEcdhGmAesCbcCmac128          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2}
	OidPaceEcdhGmAesCbcCmac192          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 3}
	OidPaceEcdhGmAesCbcCmac256          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 4}
	OidPaceDhIm                         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3}
	OidPaceDhIm3DesCbcCbc               = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 1}
	OidPaceDhImAesCbcCmac128            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 2}
	OidPaceDhImAesCbcCmac192            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 3}
	OidPaceDhImAesCbcCmac256            = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 3, 4}
	OidPaceEcdhIm                       = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4}
	OidPaceEcdhIm3DesCbcCbc             = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 1}
	OidPaceEcdhImAesCbcCmac128          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 2}
	OidPaceEcdhImAesCbcCmac192          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 3}
	OidPaceEcdhImAesCbcCmac256          = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 4, 4}
	OidPaceEcdhCam                      = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6}
	OidPaceEcdhCamAesCbcCmac128         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 2}
	OidPaceEcdhCamAesCbcCmac192         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 3}
	OidPaceEcdhCamAesCbcCmac256         = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 2, 2, 4, 6, 4}
	OidSecurityObject                   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 3, 2, 1}
	OidPrimeField                       = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
	OidEcPublicKey                      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OidPrime192v1                       = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 1}
	OidPrime256v1                       = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OidEcdsaWithSHA1                    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OidEcdsaWithSHA224                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	OidEcdsaWithSHA256                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OidEcdsaWithSHA384                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OidEcdsaWithSHA512                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OidRsaEncryption                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OidSha1WithRsaEncryption            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OidMgf1                             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	OidRsaSsaPss                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OidSha256WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OidSha384WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OidSha512WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OidSha224WithRSAEncryption          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	OidIdData                           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OidSignedData                       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OidEmailAddress                     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	OidContentType                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OidMessageDigest                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OidSigningTime                      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OidHashAlgorithmMD5                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	OidHashAlgorithmSHA1                = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OidIcao                             = asn1.ObjectIdentifier{1, 3, 27}
	OidIcaoMrtdSecurity                 = asn1.ObjectIdentifier{1, 3, 27, 1, 1}
	OidIcaoMrtdSecurityAaProtocolObject = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 5}
	OidEfDir                            = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 13}
	OidBrainpoolP192r1                  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 3}
	OidBrainpoolP224r1                  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 5}
	OidBrainpoolP256r1                  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	OidBrainpoolP320r1                  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 9}
	OidBrainpoolP384r1                  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	OidBrainpoolP512r1                  = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
	OidSecp224r1                        = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OidSecp384r1                        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OidSecp521r1                        = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	OidNameChange                       = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 6, 1}
	OidCommonName                       = asn1.ObjectIdentifier{2, 5, 4, 3}
	OidSerialNumber                     = asn1.ObjectIdentifier{2, 5, 4, 5}
	OidCountryName                      = asn1.ObjectIdentifier{2, 5, 4, 6}
	OidLocalityName                     = asn1.ObjectIdentifier{2, 5, 4, 7}
	OidStateOrProvinceName              = asn1.ObjectIdentifier{2, 5, 4, 8}
	OidOrganizationName                 = asn1.ObjectIdentifier{2, 5, 4, 10}
	OidOrganizationalUnitName           = asn1.ObjectIdentifier{2, 5, 4, 11}
	OidSubjectKeyIdentifier             = asn1.ObjectIdentifier{2, 5, 29, 14}
	OidCeKeyUsage                       = asn1.ObjectIdentifier{2, 5, 29, 15}
	OidPrivateKeyUsagePeriod            = asn1.ObjectIdentifier{2, 5, 29, 16}
	OidSubjectAltName                   = asn1.ObjectIdentifier{2, 5, 29, 17}
	OidCeIssuerAltName                  = asn1.ObjectIdentifier{2, 5, 29, 18}
	OidCeBasicConstraints               = asn1.ObjectIdentifier{2, 5, 29, 19}
	OidCeCRLDistributionPoints          = asn1.ObjectIdentifier{2, 5, 29, 31}
	OidCertificatePolicies              = asn1.ObjectIdentifier{2, 5, 29, 32}
	OidAuthorityKeyIdentifier           = asn1.ObjectIdentifier{2, 5, 29, 35}
	OidHashAlgorithmSHA256              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OidHashAlgorithmSHA384              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OidHashAlgorithmSHA512              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OidHashAlgorithmSHA224              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	OidLdsSecurityObject                = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	OidDocumentTypeList                 = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 6, 2}
)

var oidLookup = map[string]string{
	OidBsiDe.String():                            "bsi-de",
	OidBsiDeAlgorithms.String():                  "algorithms",
	OidBsiDeEcKeyType.String():                   "keyType",
	OidBsiDeProtocols.String():                   "protocols",
	OidBsiDeProtocolsSmartcard.String():          "smartcards",
	OidPk.String():                               "id-PK",
	OidPkDh.String():                             "id-PK-DH",
	OidPkEcdh.String():                           "id-PK-ECDH",
	OidTa.String():                               "id-TA",
	OidTaRsa.String():                            "id-TA-RSA",
	OidTaRsaPssSha256.String():                   "id-TA-RSA-PSS-SHA-256",
	OidTaRsaPssSha512.String():                   "id-TA-RSA-PSS-SHA-512",
	OidTaEcdsa.String():                          "id-TA-ECDSA",
	OidTaEcdsaSha224.String():                    "id-TA-ECDSA-SHA-224",
	OidTaEcdsaSha256.String():                    "id-TA-ECDSA-SHA-256",
	OidTaEcdsaSha384.String():                    "id-TA-ECDSA-SHA-384",
	OidTaEcdsaSha512.String():                    "id-TA-ECDSA-SHA-512",
	OidCa.String():                               "id-CA",
	OidCaDh.String():                             "id-CA-DH",
	OidCaDh3DesCbcCbc.String():                   "id-CA-DH-3DES-CBC-CBC",
	OidCaDhAesCbcCmac128.String():                "id-CA-DH-AES-CBC-CMAC-128",
	OidCaDhAesCbcCmac192.String():                "id-CA-DH-AES-CBC-CMAC-192",
	OidCaDhAesCbcCmac256.String():                "id-CA-DH-AES-CBC-CMAC-256",
	OidCaEcdh.String():                           "id-CA-ECDH",
	OidCaEcdh3DesCbcCbc.String():                 "id-CA-ECDH-3DES-CBC-CBC",
	OidCaEcdhAesCbcCmac128.String():              "id-CA-ECDH-AES-CBC-CMAC-128",
	OidCaEcdhAesCbcCmac192.String():              "id-CA-ECDH-AES-CBC-CMAC-192",
	OidCaEcdhAesCbcCmac256.String():              "id-CA-ECDH-AES-CBC-CMAC-256",
	OidPace.String():                             "id-PACE",
	OidPaceDhGm.String():                         "id-PACE-DH-GM",
	OidPaceDhGm3DesCbcCbc.String():               "id-PACE-DH-GM-3DES-CBC-CBC",
	OidPaceDhGmAesCbcCmac128.String():            "id-PACE-DH-GM-AES-CBC-CMAC-128",
	OidPaceDhGmAesCbcCmac192.String():            "id-PACE-DH-GM-AES-CBC-CMAC-192",
	OidPaceDhGmAesCbcCmac256.String():            "id-PACE-DH-GM-AES-CBC-CMAC-256",
	OidPaceEcdhGm.String():                       "id-PACE-ECDH-GM",
	OidPaceEcdhGm3DesCbcCbc.String():             "id-PACE-ECDH-GM-3DES-CBC-CBC",
	OidPaceEcdhGmAesCbcCmac128.String():          "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
	OidPaceEcdhGmAesCbcCmac192.String():          "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
	OidPaceEcdhGmAesCbcCmac256.String():          "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
	OidPaceDhIm.String():                         "id-PACE-DH-IM",
	OidPaceDhIm3DesCbcCbc.String():               "id-PACE-DH-IM-3DES-CBC-CBC",
	OidPaceDhImAesCbcCmac128.String():            "id-PACE-DH-IM-AES-CBC-CMAC-128",
	OidPaceDhImAesCbcCmac192.String():            "id-PACE-DH-IM-AES-CBC-CMAC-192",
	OidPaceDhImAesCbcCmac256.String():            "id-PACE-DH-IM-AES-CBC-CMAC-256",
	OidPaceEcdhIm.String():                       "id-PACE-ECDH-IM",
	OidPaceEcdhIm3DesCbcCbc.String():             "id-PACE-ECDH-IM-3DES-CBC-CBC",
	OidPaceEcdhImAesCbcCmac128.String():          "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
	OidPaceEcdhImAesCbcCmac192.String():          "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
	OidPaceEcdhImAesCbcCmac256.String():          "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
	OidPaceEcdhCam.String():                      "id-PACE-ECDH-CAM",
	OidPaceEcdhCamAesCbcCmac128.String():         "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
	OidPaceEcdhCamAesCbcCmac192.String():         "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
	OidPaceEcdhCamAesCbcCmac256.String():         "id-PACE-ECDH-CAM-AES-CBC-CMAC-256",
	OidSecurityObject.String():                   "id-SecurityObject",
	OidPrimeField.String():                       "prime-field",
	OidEcPublicKey.String():                      "id-ecPublicKey",
	OidPrime192v1.String():                       "prime192v1",
	OidPrime256v1.String():                       "prime256v1",
	OidEcdsaWithSHA1.String():                    "ecdsa-with-SHA1",
	OidEcdsaWithSHA224.String():                  "ecdsa-with-SHA224",
	OidEcdsaWithSHA256.String():                  "ecdsa-with-SHA256",
	OidEcdsaWithSHA384.String():                  "ecdsa-with-SHA384",
	OidEcdsaWithSHA512.String():                  "ecdsa-with-SHA512",
	OidRsaEncryption.String():                    "rsaEncryption",
	OidSha1WithRsaEncryption.String():            "sha1-with-rsa-signature",
	OidMgf1.String():                             "id-mgf1",
	OidRsaSsaPss.String():                        "id-RSASSA-PSS",
	OidSha256WithRSAEncryption.String():          "sha256WithRSAEncryption",
	OidSha384WithRSAEncryption.String():          "sha384WithRSAEncryption",
	OidSha512WithRSAEncryption.String():          "sha512WithRSAEncryption",
	OidSha224WithRSAEncryption.String():          "sha224WithRSAEncryption",
	OidIdData.String():                           "id-data",
	OidSignedData.String():                       "id-signedData",
	OidEmailAddress.String():                     "emailAddress",
	OidContentType.String():                      "contentType",
	OidMessageDigest.String():                    "id-messageDigest",
	OidSigningTime.String():                      "signing-time",
	OidHashAlgorithmMD5.String():                 "md5",
	OidHashAlgorithmSHA1.String():                "sha1",
	OidIcao.String():                             "id-icao",
	OidIcaoMrtdSecurity.String():                 "id-icao-mrtd-security",
	OidIcaoMrtdSecurityAaProtocolObject.String(): "id-icao-mrtd-security-aaProtocolObject",
	OidEfDir.String():                            "id-EFDIR",
	OidBrainpoolP192r1.String():                  "brainpoolP192r1",
	OidBrainpoolP224r1.String():                  "brainpoolP224r1",
	OidBrainpoolP256r1.String():                  "brainpoolP256r1",
	OidBrainpoolP320r1.String():                  "brainpoolP320r1",
	OidBrainpoolP384r1.String():                  "brainpoolP384r1",
	OidBrainpoolP512r1.String():                  "brainpoolP512r1",
	OidSecp224r1.String():                        "secp224r1",
	OidSecp384r1.String():                        "secp384r1",
	OidSecp521r1.String():                        "secp521r1",
	OidNameChange.String():                       "nameChange",
	OidCommonName.String():                       "commonName",
	OidSerialNumber.String():                     "serialNumber",
	OidCountryName.String():                      "countryName",
	OidLocalityName.String():                     "localityName",
	OidStateOrProvinceName.String():              "stateOrProvinceName",
	OidOrganizationName.String():                 "organizationName",
	OidOrganizationalUnitName.String():           "organizationalUnitName",
	OidSubjectKeyIdentifier.String():             "subjectKeyIdentifier",
	OidCeKeyUsage.String():                       "id-ce-keyUsage",
	OidPrivateKeyUsagePeriod.String():            "privateKeyUsagePeriod",
	OidSubjectAltName.String():                   "subjectAltName",
	OidCeIssuerAltName.String():                  "id-ce-issuerAltName",
	OidCeBasicConstraints.String():               "id-ce-basicConstraints",
	OidCeCRLDistributionPoints.String():          "id-ce-cRLDistributionPoints",
	OidCertificatePolicies.String():              "certificatePolicies",
	OidAuthorityKeyIdentifier.String():           "authorityKeyIdentifier",
	OidHashAlgorithmSHA256.String():              "sha256",
	OidHashAlgorithmSHA384.String():              "sha384",
	OidHashAlgorithmSHA512.String():              "sha512",
	OidHashAlgorithmSHA224.String():              "sha224",
	OidLdsSecurityObject.String():                "ldsSecurityObject",
	OidDocumentTypeList.String():                 "documentTypeList",
}

// returns the OID Description (where known)
func OidDesc(oid asn1.ObjectIdentifier) string {
	return oidLookup[oid.String()]
}

// determines if 'Oid' starts with 'prefix' (but not equal to - i.e. Oid != prefix)
func OidHasPrefix(oid asn1.ObjectIdentifier, prefixOid asn1.ObjectIdentifier) bool {
	// oid must be longer than prefix
	if len(oid) <= len(prefixOid) {
		return false
	}

	return prefixOid.Equal(oid[:len(prefixOid)])
}

// gets the raw OID bytes (without the leading tag/length - 0x06,<len>)
func OidBytes(oid asn1.ObjectIdentifier) []byte {
	asn1bytes, err := asn1.Marshal(oid)
	if err != nil {
		panic(fmt.Sprintf("Unable to encode OID []int (%s)", err.Error()))
	}

	if len(asn1bytes) < 3 {
		panic("asn1 oid with tag/length must be at least 3 bytes in length")
	}

	if asn1bytes[0] != 0x06 {
		panic("asn1 oid must have tag=0x06")
	}

	if int(asn1bytes[1]) != (len(asn1bytes) - 2) {
		panic("unexpected length")
	}

	return asn1bytes[2:]
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
		panic(fmt.Sprintf("Error parsing ASN1 OID (data: %x)", data))
	}

	return oid
}
