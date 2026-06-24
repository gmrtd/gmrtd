package document

import (
	"encoding/json"
	"log"

	"github.com/gmrtd/gmrtd/iso7816"
)

type DocumentEx struct {
	Document Document         `json:"document"`
	Session  Session          `json:"session"`
	ApduLog  *iso7816.ApduLog `json:"apduLog,omitempty"`
}

func (docEx *DocumentEx) IndentedJson() string {
	b, err := json.MarshalIndent(docEx, "", "    ")
	if err != nil {
		log.Panicf("MarshalIndent error: %s", err)
	}

	return string(b)
}
