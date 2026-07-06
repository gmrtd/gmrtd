package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/htmlreport"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/verifier"
	"github.com/pkg/browser"
)

func cmdParams(args []string) (filePath string, debug bool, challenge []byte, err error) {
	fs := flag.NewFlagSet("gmrtd-verify", flag.ContinueOnError)

	fileFlag := fs.String("file", "", "Path to CBOR document file (use - for stdin)")
	debugFlag := fs.Bool("debug", false, "Debug")
	challengeFlag := fs.String("challenge", "", "8-byte AA nonce challenge (hex, e.g. 0102030405060708)")

	if parseErr := fs.Parse(args); parseErr != nil {
		return "", false, nil, parseErr
	}

	if *fileFlag == "" {
		fs.PrintDefaults()
		return "", false, nil, fmt.Errorf("usage: -file is required")
	}

	var challengeBytes []byte
	if *challengeFlag != "" {
		challengeBytes, err = hex.DecodeString(*challengeFlag)
		if err != nil {
			return "", false, nil, fmt.Errorf("invalid -challenge: %w", err)
		}
		if len(challengeBytes) != 8 {
			return "", false, nil, fmt.Errorf("-challenge must be exactly 8 bytes (16 hex chars), got %d hex chars (%d bytes)", len(*challengeFlag), len(challengeBytes))
		}
	}

	return *fileFlag, *debugFlag, challengeBytes, nil
}

func initLogging(debug bool) {
	logLevel := &slog.LevelVar{}
	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
	if debug {
		logLevel.Set(slog.LevelDebug.Level())
	}
}

func cscaMasterList() (cms.CertPool, error) {
	pool, err := cms.DefaultMasterList()
	if err != nil {
		return nil, fmt.Errorf("[cscaMasterList] cms.DefaultMasterList error: %w", err)
	}
	return pool, nil
}

func readCborFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func verifyDocument(cscaCertPool cms.CertPool, challenge []byte, data []byte) (*document.DocumentEx, error) {
	v := verifier.NewVerifier(cscaCertPool)
	if challenge != nil {
		var err error
		v, err = v.WithAAChallenge(challenge)
		if err != nil {
			return nil, err
		}
	}
	return v.Verify(data)
}

type appDeps struct {
	cscaMasterList   func() (cms.CertPool, error)
	readFile         func(path string) ([]byte, error)
	verify           func(cscaCertPool cms.CertPool, challenge []byte, data []byte) (*document.DocumentEx, error)
	generateDocument func(*document.DocumentEx, *iso7816.ApduLog) (*bytes.Buffer, error)
	openBrowser      func(io.Reader) error
}

func defaultAppDeps() appDeps {
	return appDeps{
		cscaMasterList:   cscaMasterList,
		readFile:         readCborFile,
		verify:           verifyDocument,
		generateDocument: htmlreport.Generate,
		openBrowser:      browser.OpenReader,
	}
}

func run(args []string) error {
	return runWithDeps(args, defaultAppDeps())
}

func runWithDeps(args []string, deps appDeps) error {
	fmt.Printf("GMRTD:v%s\n\n", version.Version)

	filePath, debug, challenge, err := cmdParams(args)
	if err != nil {
		return err
	}

	initLogging(debug)

	cscaCertPool, err := deps.cscaMasterList()
	if err != nil {
		slog.Error("cscaMasterList error", "error", err)
		return err
	}

	cborData, err := deps.readFile(filePath)
	if err != nil {
		slog.Error("readFile error", "error", err)
		return err
	}

	documentEx, err := deps.verify(cscaCertPool, challenge, cborData)
	if err != nil {
		slog.Error("verify error", "error", err)
		return err
	}

	docByteBuf, err := deps.generateDocument(documentEx, nil)
	if err != nil {
		slog.Error("generateDocument error", "error", err)
		return err
	}

	err = deps.openBrowser(docByteBuf)
	if err != nil {
		slog.Error("browser.OpenReader error", "error", err)
		return err
	}

	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Printf("%s", err)
		os.Exit(1)
	}
}
