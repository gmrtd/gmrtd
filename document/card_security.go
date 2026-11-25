package document

import (
	"fmt"
	"log/slog"
	"slices"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// CardSecurity is EF.CardSecurity: a CMS SignedData whose content is a set of
// SecurityInfos. It is read for PACE-CAM, to obtain the chip's signed Chip Authentication
// public key.
type CardSecurity struct {
	RawData       []byte          `json:"rawData,omitempty"`
	SD            *cms.SignedData `json:"sd,omitempty"`
	SecurityInfos *SecurityInfos  `json:"securityInfos,omitempty"`
}

// GetRawData returns the raw EF.CardSecurity bytes as read from the chip.
func (f *CardSecurity) GetRawData() []byte { return f.RawData }

// NewCardSecurity parses EF.CardSecurity as a CMS SignedData and decodes the
// SecurityInfos in its content. It returns nil and no error if data is empty, and an
// error if the SignedData is malformed, its content type is not id-SecurityObject or the
// SecurityInfos cannot be decoded. The signature is not verified here; see the
// passiveauth package.
func NewCardSecurity(data []byte) (out *CardSecurity, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	out = new(CardSecurity)

	out.RawData = slices.Clone(data)

	slog.Debug("NewCardSecurity", "bytes", utils.BytesToHex(out.RawData))

	// NB no root node for CardSecurity, so directly parse ASN1 SignedData

	{
		var sd *cms.SignedData
		var err error

		sd, err = cms.ParseSignedData(out.RawData)
		if err != nil {
			return nil, err
		}

		out.SD = sd

		// verify the content-type is as expected
		if !sd.Content.EContentType.Equal(oid.OidSecurityObject) {
			return nil, fmt.Errorf("incorrect ContentType (got:%s)", sd.Content.EContentType.String())
		}
		eContent := sd.Content.EContent

		if out.SecurityInfos, err = DecodeSecurityInfos(eContent); err != nil {
			return nil, err
		}
	}

	return out, nil
}
