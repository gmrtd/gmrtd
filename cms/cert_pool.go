package cms

// CertPool is a set of trusted certificates (typically CSCA certificates) that verification
// looks up issuers in. Lookups only match certificates; they do not check signatures,
// validity periods or extensions. All returns every certificate in the pool.
type CertPool interface {
	// Lookup by Subject Key Identifier (SKI)
	BySKI(ski []byte) []Certificate

	// Lookup by IssuerAndSerialNumber (RFC 5652 §5.3)
	ByIssuerAndSerial(raw []byte) ([]Certificate, error)

	// Lookup by Issuer Country
	ByIssuerCountry(countryAlpha2 string) []Certificate

	All() []Certificate
}
