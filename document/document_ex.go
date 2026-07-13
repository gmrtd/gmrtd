package document

type DocumentEx struct {
	Document Document `json:"document"`
	Session  Session  `json:"session"`
}

// Summary derives a DocumentSummary from the current Document/Session state. It is
// computed fresh on every call rather than cached - call it any time after the relevant
// session steps (Document.Verify, Passive Authentication, chip authentication) have run.
//
// IdentityAttributes is always populated from whatever DG data is present, regardless of
// DataTrusted - callers that need to distinguish an untrustworthy read (unverified SOD,
// tampered DG, etc.) from a genuinely empty document must check DataTrusted themselves
// rather than relying on IdentityAttributes's presence.
func (docEx *DocumentEx) Summary() *DocumentSummary {
	dataTrusted := docEx.Session.DocumentVerifyErr == nil &&
		docEx.Session.PassiveAuthResult != nil &&
		docEx.Session.PassiveAuthResult.Success

	return &DocumentSummary{
		DataTrusted:        dataTrusted,
		ChipAuthenticity:   docEx.Session.VerifiedChipAuthStatus(),
		LdsVersion:         docEx.Document.LdsVersion(),
		UnicodeVersion:     docEx.Document.UnicodeVersion(),
		IdentityAttributes: buildIdentityAttributes(&docEx.Document),
	}
}
