package cms

type CertPool interface {
	// Lookup by Subject Key Identifier (SKI)
	GetBySKI(ski []byte) []Certificate

	// Lookup by Issuer Country
	GetByIssuerCountry(countryAlpha2 string) []Certificate

	GetAll() []Certificate

	// Get Certificate Revocation List (CRL) for passive authentication
	GetCRL() *CertificateList
}
