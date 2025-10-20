package cms

type CertPool interface {
	// Lookup by Subject Key Identifier (SKI)
	GetBySKI(ski []byte) []Certificate

	// Lookup by Issuer Country
	GetByIssuerCountry(countryAlpha2 string) []Certificate

	GetAll() []Certificate

	// Get Certificate Revocation List (CRL) for passive authentication
	// Deprecated: CRL checking should now be done via VerifyOptions with CRL Distribution Points
	// This method is kept for backward compatibility only
	GetCRL() *CertificateList
}
