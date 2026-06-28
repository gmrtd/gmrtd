package document

import (
	"github.com/gmrtd/gmrtd/iso7816"
)

type DocumentEx struct {
	Document Document         `json:"document"`
	Session  Session          `json:"session"`
	ApduLog  *iso7816.ApduLog `json:"apduLog,omitempty"`
}

func (docEx *DocumentEx) GenerateSummary() {
	docEx.Session.Summary = &DocumentSummary{
		DataTrusted: docEx.Session.PassiveAuthResult != nil &&
			docEx.Session.PassiveAuthResult.Success,
		ChipAuthenticity: docEx.Session.VerifiedChipAuthStatus(),
		LdsVersion:       docEx.Document.LdsVersion(),
		UnicodeVersion:   docEx.Document.UnicodeVersion(),
	}
}

