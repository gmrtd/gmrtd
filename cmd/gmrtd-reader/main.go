package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"os"

	"github.com/dumacp/smartcard/pcsc"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/pkg/browser"
)

//go:embed templates/*
var templateFS embed.FS

type PCSCTransceiver struct {
	card pcsc.Card
}

func (transceiver *PCSCTransceiver) Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) (rApduBytes []byte) {
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

var tmpl *template.Template

func outputDocument(document *document.Document) {
	var err error

	if document == nil {
		return
	}

	funcMap := template.FuncMap{
		"BytesToHex":       func(bytes []byte) string { return fmt.Sprintf("%X", bytes) },
		"TlvBytesToString": func(bytes []byte) string { nodes, _ := tlv.Decode(bytes); return nodes.String() },
		"BytesToBase64":    func(bytes []byte) string { return base64.StdEncoding.EncodeToString(bytes) },
		"ApduTotalDurMs": func(apdus []iso7816.ApduLog) int {
			var totalMs int
			for _, apdu := range apdus {
				totalMs += apdu.DurMs
			}
			return totalMs
		},
	}

	tmpl, err = template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.gohtml")
	if err != nil {
		log.Fatalln(err)
	}

	byteBuf := bytes.NewBuffer(nil)

	// convert to HTML using template
	err = tmpl.ExecuteTemplate(byteBuf, "output.gohtml", document)
	if err != nil {
		log.Fatalln(err)
	}

	// display in default browser
	err = browser.OpenReader(byteBuf)
	if err != nil {
		log.Fatalln(err)
	}
}

func getParams() (pass *password.Password, debug bool, apduMaxRead uint, skipPace bool, err error) {
	documentNo := flag.String("doc", "", "Document Number")
	dateOfBirth := flag.String("dob", "", "Date of Birth (YYMMDD)")
	expiryDate := flag.String("exp", "", "Expiry Date (YYMMDD)")
	can := flag.String("can", "", "Card Access Number")
	debugFlag := flag.Bool("debug", false, "Debug")
	maxRead := flag.Uint("maxRead", 0, "Maximum read amount (bytes) e.g. 1..65536")
	skipPaceFlag := flag.Bool("skipPace", false, "Skip PACE")

	flag.Parse()

	if len(*documentNo) > 0 && len(*dateOfBirth) == 6 && len(*expiryDate) == 6 {
		pass, err = password.NewPasswordMrzi(*documentNo, *dateOfBirth, *expiryDate)
		if err != nil {
			return nil, false, 0, false, err
		}
	} else if len(*can) > 0 {
		pass = password.NewPasswordCan(*can)
	} else {
		flag.PrintDefaults()
		return nil, false, 0, false, fmt.Errorf("usage: must specify either doc+dob+exp *OR* can")
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

func main() {
	var pass *password.Password
	var debug bool = false
	var maxRead uint = 0
	var skipPace bool = false
	var err error

	pass, debug, maxRead, skipPace, err = getParams()
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}

	initLogging(debug)

	ctx, err := pcsc.NewContext()
	if err != nil {
		slog.Error("Unable to initialise PCSC")
		os.Exit(1)
	}
	defer ctx.Release()

	readers, err := pcsc.ListReaders(ctx)
	if err != nil {
		slog.Error("Unable to get PCSC readers")
		os.Exit(1)
	}
	slog.Debug("PCSC", "readers", readers)

	if len(readers) < 1 {
		slog.Error("No PCSC reader found")
		os.Exit(1)
	}

	// NB we currently just select the 1st reader (if multiple)
	pcscReader := pcsc.NewReader(ctx, readers[0])

	card, err := pcscReader.ConnectCardPCSC()
	if err != nil {
		slog.Error("No chip detected")
		os.Exit(1)
	}
	defer card.DisconnectCard()

	atr, _ := card.ATR()
	ats, _ := card.ATS()

	var transceiver *PCSCTransceiver = new(PCSCTransceiver)

	transceiver.card = card

	var status *PCSCReaderStatus = new(PCSCReaderStatus)

	var reader *reader.Reader = reader.NewReader(status)

	// set APDU Max Read (if specified)
	if maxRead > 0 {
		reader.SetApduMaxLe(int(maxRead))
	}

	// skip PACE (if specified)
	if skipPace {
		reader.SkipPace()
	}

	// read (and verify) the document (inc passive-authentication)
	document, err := reader.ReadDocument(transceiver, pass, atr, ats)
	if err != nil {
		// output whatever we have from the document
		outputDocument(document)
		slog.Error("ReadDocument", "error", err)
		os.Exit(1)
	}

	outputDocument(document)
}
