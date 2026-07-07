package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/dumacp/smartcard/pcsc"
	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/htmlreport"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/passiveauth"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/pkg/browser"
)

type PCSCTransceiver struct {
	card smartCard
}

var _ iso7816.Transceiver = (*PCSCTransceiver)(nil)

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

var _ reader.ReaderStatus = (*PCSCReaderStatus)(nil)

func (status *PCSCReaderStatus) Status(msg string) {
	slog.Info("Status", "msg", msg)
}

func cmdParams(args []string) (pass *password.Password, debug bool, apduMaxRead uint, skipPace bool, skipImages bool, sampleDoc bool, err error) {
	fs := flag.NewFlagSet("gmrtd-reader", flag.ContinueOnError)

	documentNo := fs.String("doc", "", "Document Number")
	dateOfBirth := fs.String("dob", "", "Date of Birth (YYMMDD)")
	expiryDate := fs.String("exp", "", "Expiry Date (YYMMDD)")
	can := fs.String("can", "", "Card Access Number")
	debugFlag := fs.Bool("debug", false, "Debug")
	maxRead := fs.Uint("maxRead", 0, "Maximum read amount (bytes) e.g. 1..65536")
	skipPaceFlag := fs.Bool("skipPace", false, "Skip PACE")
	skipImagesFlag := fs.Bool("skipImages", false, "Skip image data groups (DG2, DG7)")
	sampleDocFlag := fs.Bool("sampleDoc", false, "Generate the HTML report from static sample data instead of reading a card")

	if err := fs.Parse(args); err != nil {
		return nil, false, 0, false, false, false, err
	}

	// sample-document mode bypasses card credentials entirely - no card is read
	if *sampleDocFlag {
		return nil, *debugFlag, *maxRead, *skipPaceFlag, *skipImagesFlag, true, nil
	}

	if len(*documentNo) > 0 && len(*dateOfBirth) == 6 && len(*expiryDate) == 6 {
		pass, err = password.NewPasswordMrzi(*documentNo, *dateOfBirth, *expiryDate)
		if err != nil {
			return nil, false, 0, false, false, false, err
		}
	} else if len(*can) > 0 {
		pass = password.NewPasswordCan(*can)
	} else {
		fs.PrintDefaults()
		return nil, false, 0, false, false, false, fmt.Errorf("usage: must specify either doc+dob+exp *OR* can")
	}

	if *maxRead > 65536 {
		return nil, false, 0, false, false, false, fmt.Errorf("maxRead must be 0 or between 1 and 65536")
	}

	return pass, *debugFlag, *maxRead, *skipPaceFlag, *skipImagesFlag, false, nil
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
	generateDocument     func(*document.DocumentEx, *iso7816.ApduLog) (*bytes.Buffer, error)
	openBrowser          func(io.Reader) error
	readDocumentFromCard func(pass *password.Password, maxRead uint, skipPace bool, skipImages bool, card smartCard, cscaCertPool cms.CertPool) (*document.DocumentEx, *iso7816.ApduLog, error)
	sampleDocument       func(cscaCertPool cms.CertPool) (*document.DocumentEx, error)
}

func defaultAppDeps() appDeps {
	return appDeps{
		cardProvider:         newPCSCCardProvider,
		cscaMasterList:       cscaMasterList,
		generateDocument:     htmlreport.Generate,
		openBrowser:          browser.OpenReader,
		readDocumentFromCard: readDocumentFromCard,
		sampleDocument:       sampleDocument,
	}
}

// sampleDocument builds a DocumentEx from static ICAO 9303 sample data (see
// document.SampleDocument), for use with the -sampleDoc CLI flag. Passive
// Authentication is run against it (matching mobile.NewSampleDocument), but
// since the sample data groups come from different worked examples, it is
// expected to fail - the generated report will show a worked example of a
// failed-PA result.
func sampleDocument(cscaCertPool cms.CertPool) (*document.DocumentEx, error) {
	doc, err := document.SampleDocument()
	if err != nil {
		return nil, fmt.Errorf("[sampleDocument] SampleDocument error: %w", err)
	}

	docEx := &document.DocumentEx{Document: *doc}
	docEx.Session.PassiveAuthResult, docEx.Session.PassiveAuthErr = passiveauth.PassiveAuth(doc, cscaCertPool)
	docEx.GenerateSummary()

	return docEx, nil
}

func run(args []string) error {
	return runWithDeps(args, defaultAppDeps())
}

func runWithDeps(args []string, deps appDeps) error {
	var pass *password.Password
	var debug bool = false
	var maxRead uint = 0
	var skipPace bool = false
	var skipImages bool = false
	var sampleDoc bool = false
	var err error

	fmt.Printf("GMRTD:v%s\n\n", version.Version)

	pass, debug, maxRead, skipPace, skipImages, sampleDoc, err = cmdParams(args)
	if err != nil {
		return err
	}

	initLogging(debug)

	var documentEx *document.DocumentEx
	var apduLog *iso7816.ApduLog

	if sampleDoc {
		cscaCertPool, err := deps.cscaMasterList()
		if err != nil {
			slog.Error("cscaMasterList error", "error", err)
			return err
		}

		documentEx, err = deps.sampleDocument(cscaCertPool)
		if err != nil {
			slog.Error("sampleDocument", "error", err)
			return err
		}
	} else {
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

		documentEx, apduLog, err = deps.readDocumentFromCard(pass, maxRead, skipPace, skipImages, card, cscaCertPool)
		if err != nil {
			slog.Error("readDocumentFromCard", "error", err)
			return err
		}
	}

	// generate the HTML document
	docByteBuf, err := deps.generateDocument(documentEx, apduLog)
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
	skipImages bool,
	card smartCard,
	cscaCertPool cms.CertPool,
) (*document.DocumentEx, *iso7816.ApduLog, error) {
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

	if skipImages {
		r.SkipImages()
	}

	return r.ReadDocument(pass, atr, ats)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}
}
