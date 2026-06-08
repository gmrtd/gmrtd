package cms

type CertPool interface {
	// Lookup by Subject Key Identifier (SKI)
	BySKI(ski []byte) []Certificate

	// Lookup by IssuerAndSerialNumber (RFC 5652 §5.3)
	ByIssuerAndSerial(raw []byte) ([]Certificate, error)

	// Lookup by Issuer Country
	ByIssuerCountry(countryAlpha2 string) []Certificate

	All() []Certificate
}
