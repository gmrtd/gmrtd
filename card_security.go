package gmrtd

import (
	"fmt"
	"log/slog"
	"slices"
)

type CardSecurity struct {
	RawData       []byte
	SecurityInfos *SecurityInfos
}

func NewCardSecurity(data []byte) (out *CardSecurity, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	out = new(CardSecurity)

	out.RawData = slices.Clone(data)

	slog.Debug("NewCardSecurity", "bytes", BytesToHex(out.RawData))

	// NB no root node for CardSecurity, so directly parse ASN1 SignedData

	{
		var sd *SignedData
		var err error

		sd, err = parseSignedData(out.RawData) // TODO - maybe move singedData parsing? currently in SOD but also used here
		if err != nil {
			return nil, err
		}

		// verify the content-type is as expected
		if !sd.SD2.Content.EContentType.Equal(oidSecurityObject) {
			return nil, fmt.Errorf("incorrect ContentType (got:%s)", sd.SD2.Content.EContentType.String())
		}
		eContent := sd.SD2.Content.EContent

		if out.SecurityInfos, err = DecodeSecurityInfos(eContent); err != nil {
			return nil, err
		}
	}

	return out, nil
}
