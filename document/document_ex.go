package document

type DocumentEx struct {
	Document Document `json:"document"`
	Session  Session  `json:"session"`
}

func (docEx *DocumentEx) GenerateSummary() {
	docEx.Session.Summary = &DocumentSummary{
		DataTrusted: docEx.Session.DocumentVerifyErr == nil &&
			docEx.Session.PassiveAuthResult != nil &&
			docEx.Session.PassiveAuthResult.Success,
		ChipAuthenticity: docEx.Session.VerifiedChipAuthStatus(),
		LdsVersion:       docEx.Document.LdsVersion(),
		UnicodeVersion:   docEx.Document.UnicodeVersion(),
	}
}

