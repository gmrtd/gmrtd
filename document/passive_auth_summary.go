package document

import (
	"time"

	"github.com/gmrtd/gmrtd/cms"
)

type PassiveAuthStatus string

const (
	PASSIVE_AUTH_STATUS_VERIFIED      PassiveAuthStatus = "VERIFIED"
	PASSIVE_AUTH_STATUS_FAILED        PassiveAuthStatus = "FAILED"
	PASSIVE_AUTH_STATUS_NOT_PERFORMED PassiveAuthStatus = "NOT_PERFORMED"
)

type CertificateRole string

const (
	CERTIFICATE_ROLE_DOCUMENT_SIGNER CertificateRole = "DOCUMENT_SIGNER"
	CERTIFICATE_ROLE_CSCA            CertificateRole = "CSCA"
	CERTIFICATE_ROLE_CSCA_LINK       CertificateRole = "CSCA_LINK"
)

// PassiveAuthSummary describes the Passive Authentication outcome and trust chains for display.
type PassiveAuthSummary struct {
	Status PassiveAuthStatus `json:"status"`
	Error  string            `json:"error,omitempty"`

	Sod          *SignedObjectTrust `json:"sod,omitempty"`
	CardSecurity *SignedObjectTrust `json:"cardSecurity,omitempty"` // nil when CardSecurity is absent
}

// SignedObjectTrust is the trust chain of one signed object (EF.SOD or EF.CardSecurity).
//
// When Verified, Chain is the verified chain: each document signer certificate followed by the
// trusted CSCA (or CSCA link) certificate that issued it. Otherwise Chain only holds the
// document signer certificate(s) embedded in the object, if they can be identified. These are
// chip-supplied and UNVERIFIED: they show who claims to have signed the data, never that it is
// trustworthy.
type SignedObjectTrust struct {
	Verified bool                    `json:"verified"`
	Chain    []TrustChainCertificate `json:"chain,omitempty"`
}

type TrustChainCertificate struct {
	Role CertificateRole `json:"role"`

	// Expired reports whether the certificate has expired as of the time Summary was called.
	// It is informational: verification is at the time of signing, so an expired certificate
	// is expected for older documents and does not mean the chain is untrusted. nil when the
	// validity period can't be parsed.
	Expired *bool `json:"expired,omitempty"`

	cms.CertificateInfo
}

func buildPassiveAuthSummary(doc *Document, session *Session, now time.Time) *PassiveAuthSummary {
	result := session.PassiveAuthResult

	out := &PassiveAuthSummary{Status: PASSIVE_AUTH_STATUS_FAILED}
	switch {
	case result == nil && session.PassiveAuthErr == nil:
		out.Status = PASSIVE_AUTH_STATUS_NOT_PERFORMED
	case result != nil && result.Success:
		out.Status = PASSIVE_AUTH_STATUS_VERIFIED
	}
	if session.PassiveAuthErr != nil {
		out.Error = session.PassiveAuthErr.Error()
	}

	var sodChain, cardSecChain [][]byte
	if result != nil && result.Sod != nil {
		sodChain = result.Sod.CertChain
	}
	if result != nil && result.CardSec != nil {
		cardSecChain = result.CardSec.CertChain
	}

	if doc.Mf.Lds1.Sod != nil {
		out.Sod = signedObjectTrust(doc.Mf.Lds1.Sod.SD, sodChain, now)
	}
	if doc.Mf.CardSecurity != nil {
		out.CardSecurity = signedObjectTrust(doc.Mf.CardSecurity.SD, cardSecChain, now)
	}

	return out
}

// signedObjectTrust relies on SignedData.Verify only returning a chain on success.
func signedObjectTrust(sd *cms.SignedData, verifiedChain [][]byte, now time.Time) *SignedObjectTrust {
	if len(verifiedChain) > 0 {
		out := &SignedObjectTrust{Verified: true}
		for _, raw := range verifiedChain {
			certs, err := cms.ParseCertificates(raw)
			if err != nil || len(certs) != 1 {
				continue
			}
			out.Chain = append(out.Chain, trustChainCertificate(&certs[0], now))
		}
		return out
	}

	out := &SignedObjectTrust{}
	if sd == nil {
		return out
	}
	signers, err := sd.SignerCertificates()
	if err != nil {
		return out
	}
	for i := range signers {
		out.Chain = append(out.Chain, trustChainCertificate(&signers[i], now))
	}
	return out
}

func trustChainCertificate(cert *cms.Certificate, now time.Time) TrustChainCertificate {
	info := cert.Info()

	out := TrustChainCertificate{Role: certificateRole(cert, info), CertificateInfo: info}
	if info.NotAfter != nil {
		expired := now.After(*info.NotAfter)
		out.Expired = &expired
	}
	return out
}

// certificateRole infers the role from the certificate itself rather than its chain position,
// since chains from multiple SignerInfos are concatenated (ICAO SODs have exactly one).
func certificateRole(cert *cms.Certificate, info cms.CertificateInfo) CertificateRole {
	switch {
	case !info.CA:
		return CERTIFICATE_ROLE_DOCUMENT_SIGNER
	case cert.IsLinkCert():
		return CERTIFICATE_ROLE_CSCA_LINK
	default:
		return CERTIFICATE_ROLE_CSCA
	}
}
