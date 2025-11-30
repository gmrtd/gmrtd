package document

import (
	"encoding/json"
	"log"
)

type DocumentEx struct {
	Document Document `json:"document"`
	Session  Session  `json:"session"`
}

func (docEx *DocumentEx) IndentedJson() string {
	b, err := json.MarshalIndent(docEx, "", "    ")
	if err != nil {
		log.Panicf("MarshalIndent error: %s", err)
	}

	return string(b)
}
