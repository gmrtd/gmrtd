package cms

type CertPool interface {
	// Lookup by Subject Key Identifier (SKI)
	BySKI(ski []byte) []Certificate

	// Lookup by Issuer Country
	ByIssuerCountry(countryAlpha2 string) []Certificate

	All() []Certificate
}
