package cms

type CombinedCertPool struct {
	certPools []CertPool
}

var _ CertPool = (*CombinedCertPool)(nil)

func (cp *CombinedCertPool) AddCertPool(certPool CertPool) {
	cp.certPools = append(cp.certPools, certPool)
}

// gets matching certificates by 'subject' key identifier (ski)
func (cp *CombinedCertPool) BySKI(ski []byte) []Certificate {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts := cp.certPools[i].BySKI(ski)
		out = append(out, tmpCerts...)
	}

	return out
}

// gets matching certificates by IssuerAndSerialNumber (RFC 5652 §5.3)
func (cp *CombinedCertPool) ByIssuerAndSerial(raw []byte) ([]Certificate, error) {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts, err := cp.certPools[i].ByIssuerAndSerial(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, tmpCerts...)
	}

	return out, nil
}

// gets matching certificates by 'issuer' country
func (cp *CombinedCertPool) ByIssuerCountry(countryAlpha2 string) []Certificate {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts := cp.certPools[i].ByIssuerCountry(countryAlpha2)
		out = append(out, tmpCerts...)
	}

	return out
}

func (cp *CombinedCertPool) All() []Certificate {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts := cp.certPools[i].All()
		out = append(out, tmpCerts...)
	}

	return out
}
