package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/dumacp/smartcard/pcsc"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/pkg/browser"
)

//go:embed templates/*
var templateFS embed.FS

type PCSCTransceiver struct {
	card smartCard
}

func (transceiver *PCSCTransceiver) Transceive(_ int, _ int, _ int, _ int, _ []byte, _ int, encodedData []byte) (rApduBytes []byte) {
	rApduBytes, err := transceiver.card.Apdu(encodedData)
	if err != nil {
		slog.Error("Transceive", "error", err)
		return
	}

	slog.Debug("Transceive", "cApdu", utils.BytesToHex(encodedData), "rApdu", utils.BytesToHex(rApduBytes))

	return
}

type PCSCReaderStatus struct {
}

func (status *PCSCReaderStatus) Status(msg string) {
	slog.Info("Status", "msg", msg)
}

func templateFuncMap() template.FuncMap {
	// TODO - is 'TlvBytesToString' still required? check others also
	return template.FuncMap{
		"GmrtdVersion":     func() string { return version.Version },
		"BytesToHex":       func(bytes []byte) string { return fmt.Sprintf("%X", bytes) },
		"BytesToStr":       func(bytes []byte) string { return string(bytes) },
		"ByteLen":          func(bytes []byte) int { return len(bytes) },
		"TagToHex":         func(tag tlv.TlvTag) string { return fmt.Sprintf("%X", tag) },
		"TlvBytesToString": func(bytes []byte) string { nodes := tlv.MustDecode(bytes); return nodes.String() },
		"DecodeTlvBytes":   func(bytes []byte) []tlv.TlvNode { nodes := tlv.MustDecode(bytes); return nodes.Nodes() },
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
	}
}

func parseDocumentTemplates() (*template.Template, error) {
	return template.New("").Funcs(templateFuncMap()).ParseFS(templateFS, "templates/*.gohtml")
}

func executeDocumentTemplate(tmpl *template.Template, documentEx *document.DocumentEx) (*bytes.Buffer, error) {
	byteBuf := bytes.NewBuffer(nil)

	// convert to HTML using template
	err := tmpl.ExecuteTemplate(byteBuf, "output.gohtml", documentEx)
	if err != nil {
		return nil, fmt.Errorf("[generateDocument] ExecuteTemplate error: %w", err)
	}

	return byteBuf, nil
}

func generateDocument(documentEx *document.DocumentEx) (*bytes.Buffer, error) {
	var err error

	if documentEx == nil {
		return nil, fmt.Errorf("[generateDocument] documentEx cannot be nil")
	}

	tmpl, err := parseDocumentTemplates()
	if err != nil {
		return nil, fmt.Errorf("[generateDocument] ParseFS error: %w", err)
	}

	byteBuf, err := executeDocumentTemplate(tmpl, documentEx)
	if err != nil {
		return nil, fmt.Errorf("[generateDocument] executeDocumentTemplate error: %w", err)
	}

	return byteBuf, nil
}

func cmdParams(args []string) (pass *password.Password, debug bool, apduMaxRead uint, skipPace bool, err error) {
	fs := flag.NewFlagSet("gmrtd-reader", flag.ContinueOnError)

	documentNo := fs.String("doc", "", "Document Number")
	dateOfBirth := fs.String("dob", "", "Date of Birth (YYMMDD)")
	expiryDate := fs.String("exp", "", "Expiry Date (YYMMDD)")
	can := fs.String("can", "", "Card Access Number")
	debugFlag := fs.Bool("debug", false, "Debug")
	maxRead := fs.Uint("maxRead", 0, "Maximum read amount (bytes) e.g. 1..65536")
	skipPaceFlag := fs.Bool("skipPace", false, "Skip PACE")

	if err := fs.Parse(args); err != nil {
		return nil, false, 0, false, err
	}

	if len(*documentNo) > 0 && len(*dateOfBirth) == 6 && len(*expiryDate) == 6 {
		pass, err = password.NewPasswordMrzi(*documentNo, *dateOfBirth, *expiryDate)
		if err != nil {
			return nil, false, 0, false, err
		}
	} else if len(*can) > 0 {
		pass = password.NewPasswordCan(*can)
	} else {
		fs.PrintDefaults()
		return nil, false, 0, false, fmt.Errorf("usage: must specify either doc+dob+exp *OR* can")
	}

	if *maxRead > 65536 {
		return nil, false, 0, false, fmt.Errorf("maxRead must be 0 or between 1 and 65536")
	}

	return pass, *debugFlag, *maxRead, *skipPaceFlag, nil
}

func initLogging(debug bool) {
	logLevel := &slog.LevelVar{}
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
	if debug {
		logLevel.Set(slog.LevelDebug.Level()) // enable debug
	}
}

func cscaMasterList() (cms.CertPool, error) {
	var cscaCertPool cms.CertPool
	var err error

	cscaCertPool, err = cms.DefaultMasterList()
	if err != nil {
		return nil, fmt.Errorf("[cscaMasterList] cms.DefaultMasterList error: %w", err)
	}

	return cscaCertPool, nil
}

type smartCard interface {
	ATR() ([]byte, error)
	ATS() ([]byte, error)
	Apdu([]byte) ([]byte, error)
	DisconnectCard() error
}

type cardProvider interface {
	ConnectCard() (smartCard, error)
}

type pcscCardProvider struct {
	ctx *pcsc.Context
}

func newPCSCCardProvider() (cardProvider, error) {
	ctx, err := pcsc.NewContext()
	if err != nil {
		return nil, err
	}

	readers, err := pcsc.ListReaders(ctx)
	if err != nil {
		ctx.Release()
		return nil, err
	}

	if len(readers) < 1 {
		ctx.Release()
		return nil, fmt.Errorf("no PCSC reader found")
	}

	return &pcscCardProvider{ctx: ctx}, nil
}

func (p *pcscCardProvider) ConnectCard() (smartCard, error) {
	readers, err := pcsc.ListReaders(p.ctx)
	if err != nil {
		return nil, err
	}

	pcscReader := pcsc.NewReader(p.ctx, readers[0])
	return pcscReader.ConnectCardPCSC()
}

type appDeps struct {
	cardProvider         func() (cardProvider, error)
	cscaMasterList       func() (cms.CertPool, error)
	generateDocument     func(*document.DocumentEx) (*bytes.Buffer, error)
	openBrowser          func(io.Reader) error
	readDocumentFromCard func(pass *password.Password, maxRead uint, skipPace bool, card smartCard, cscaCertPool cms.CertPool) (*document.DocumentEx, error)
}

func defaultAppDeps() appDeps {
	return appDeps{
		cardProvider:         newPCSCCardProvider,
		cscaMasterList:       cscaMasterList,
		generateDocument:     generateDocument,
		openBrowser:          browser.OpenReader,
		readDocumentFromCard: readDocumentFromCard,
	}
}

func run(args []string) error {
	return runWithDeps(args, defaultAppDeps())
}

func runWithDeps(args []string, deps appDeps) error {
	var pass *password.Password
	var debug bool = false
	var maxRead uint = 0
	var skipPace bool = false
	var err error

	fmt.Printf("GMRTD:v%s\n\n", version.Version)

	pass, debug, maxRead, skipPace, err = cmdParams(args)
	if err != nil {
		return err
	}

	initLogging(debug)

	provider, err := deps.cardProvider()
	if err != nil {
		return err
	}

	card, err := provider.ConnectCard()
	if err != nil {
		return err
	}
	defer card.DisconnectCard()

	cscaCertPool, err := deps.cscaMasterList()
	if err != nil {
		slog.Error("cscaMasterList error", "error", err)
		return err
	}

	documentEx, err := deps.readDocumentFromCard(pass, maxRead, skipPace, card, cscaCertPool)
	if err != nil {
		slog.Error("readDocumentFromCard", "error", err)
		return err
	}

	// generate the HTML document
	docByteBuf, err := deps.generateDocument(documentEx)
	if err != nil {
		slog.Error("generateDocument", "error", err)
		return err
	}

	// display in default browser
	err = deps.openBrowser(docByteBuf)
	if err != nil {
		slog.Error("browser.OpenReader", "error", err)
		return err
	}

	return nil
}

func readDocumentFromCard(
	pass *password.Password,
	maxRead uint,
	skipPace bool,
	card smartCard,
	cscaCertPool cms.CertPool,
) (*document.DocumentEx, error) {
	atr, err := card.ATR()
	if err != nil {
		slog.Warn("ATR error", "error", err)
	}

	ats, err := card.ATS()
	if err != nil {
		slog.Warn("ATS error", "error", err)
	}

	transceiver := &PCSCTransceiver{card: card}
	status := &PCSCReaderStatus{}

	nfc := iso7816.NewNfcSession(transceiver)
	if maxRead > 0 {
		nfc.SetMaxLe(int(maxRead))
	}

	r := reader.NewReader(status, nfc, cscaCertPool)
	if skipPace {
		r.SkipPace()
	}

	return r.ReadDocument(pass, atr, ats)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}
