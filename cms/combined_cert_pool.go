package cms

type CombinedCertPool struct {
	certPools []CertPool
}

func (cp *CombinedCertPool) AddCertPool(certPool CertPool) {
	cp.certPools = append(cp.certPools, certPool)
}

// gets matching certificates by 'subject' key identifier (ski)
func (cp *CombinedCertPool) GetBySKI(ski []byte) []Certificate {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts := cp.certPools[i].GetBySKI(ski)
		out = append(out, tmpCerts...)
	}

	return out
}

// gets matching certificates by 'issuer' country
func (cp *CombinedCertPool) GetByIssuerCountry(countryAlpha2 string) []Certificate {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts := cp.certPools[i].GetByIssuerCountry(countryAlpha2)
		out = append(out, tmpCerts...)
	}

	return out
}

func (cp *CombinedCertPool) GetAll() []Certificate {
	var out []Certificate

	for i := range cp.certPools {
		tmpCerts := cp.certPools[i].GetAll()
		out = append(out, tmpCerts...)
	}

	return out
}
