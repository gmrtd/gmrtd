package htmlreport

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

//go:embed templates/*
var templateFS embed.FS

type templateData struct {
	*document.DocumentEx
	ApduLog    *iso7816.ApduLog
	CborBase64 string
}

func templateFuncMap() template.FuncMap {
	return template.FuncMap{
		"GmrtdVersion":   func() string { return version.Version },
		"BytesToHex":     func(bytes []byte) string { return fmt.Sprintf("%X", bytes) },
		"BytesToStr":     func(bytes []byte) string { return string(bytes) },
		"ByteLen":        func(bytes []byte) int { return len(bytes) },
		"TagToHex":       func(tag tlv.TlvTag) string { return fmt.Sprintf("%X", tag) },
		"DecodeTlvBytes": func(bytes []byte) []tlv.TlvNode { nodes := tlv.MustDecode(bytes); return nodes.Nodes() },
		"BytesToBase64":    func(bytes []byte) string { return base64.StdEncoding.EncodeToString(bytes) },
		"OidDesc": func(oidBytes []byte) string {
			tmpOid := oid.DecodeAsn1objectId(oidBytes)
			tmpOidDesc := oid.OidDesc(tmpOid)
			return fmt.Sprintf("%s %s", tmpOid.String(), tmpOidDesc)
		},
		"IsPrintable": func(bytes []byte) bool { return len(bytes) > 0 && utils.PrintableBytes(bytes) },
		"ApduTotalDurMs": func(entries []*iso7816.ApduLogEntry) int {
			var totalMs int
			for _, entry := range entries {
				totalMs += int(entry.DurMs)
			}
			return totalMs
		},
		"IndentedJson": func(v any) string {
			b, err := json.MarshalIndent(v, "", "    ")
			if err != nil {
				log.Panicf("MarshalIndent error: %s", err)
			}
			return string(b)
		},
	}
}

func parseDocumentTemplates() (*template.Template, error) {
	return template.New("").Funcs(templateFuncMap()).ParseFS(templateFS, "templates/*.gohtml")
}

func executeDocumentTemplate(tmpl *template.Template, data *templateData) (*bytes.Buffer, error) {
	byteBuf := bytes.NewBuffer(nil)

	err := tmpl.ExecuteTemplate(byteBuf, "output.gohtml", data)
	if err != nil {
		return nil, fmt.Errorf("[generateDocument] ExecuteTemplate error: %w", err)
	}

	return byteBuf, nil
}

// Generate renders a DocumentEx (plus, if available, the APDU log captured during the
// read/verify) to an HTML report.
func Generate(documentEx *document.DocumentEx, apduLog *iso7816.ApduLog) (*bytes.Buffer, error) {
	if documentEx == nil {
		return nil, fmt.Errorf("[generateDocument] documentEx cannot be nil")
	}

	tmpl, err := parseDocumentTemplates()
	if err != nil {
		return nil, fmt.Errorf("[generateDocument] ParseFS error: %w", err)
	}

	data := &templateData{DocumentEx: documentEx, ApduLog: apduLog}

	cborBytes, err := documentEx.ToCbor()
	if err != nil {
		slog.Warn("ToCbor failed, CBOR section will be unavailable", "error", err)
	} else {
		data.CborBase64 = base64.StdEncoding.EncodeToString(cborBytes)
	}

	byteBuf, err := executeDocumentTemplate(tmpl, data)
	if err != nil {
		return nil, fmt.Errorf("[generateDocument] executeDocumentTemplate error: %w", err)
	}

	return byteBuf, nil
}
