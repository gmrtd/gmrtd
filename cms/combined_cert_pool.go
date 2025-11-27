package cms

type CombinedCertPool struct {
	certPools []CertPool
}

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
