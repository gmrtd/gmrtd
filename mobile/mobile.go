package mobile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso3166"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
	"github.com/gmrtd/gmrtd/verifier"
)

var (
	cscaOnce     sync.Once
	cscaCertPool cms.CertPool
	cscaInitErr  error
)

func PreloadCscaCertPool() error {
	cscaOnce.Do(func() {
		cscaCertPool, cscaInitErr = cms.DefaultMasterList()
	})
	return cscaInitErr
}

func getCscaCertPool() (cms.CertPool, error) {
	if err := PreloadCscaCertPool(); err != nil {
		return nil, err
	}
	return cscaCertPool, nil
}

// bind doesn't like referencing iso7816.Transceiver
// so we redefine the interface here
type Transceiver interface {
	Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) []byte
}

// bind doesn't like referencing reader.ReaderStatus
// so we redefine the interface here
type ReaderStatus interface {
	Status(msg string)
}

type MrtdPassword struct {
	password *password.Password
}

func Version() string {
	return version.Version
}

func NewPasswordMrz(mrz string) (*MrtdPassword, error) {
	var err error
	var pass *password.Password

	pass, err = password.NewPasswordMrz(mrz)
	if err != nil {
		return nil, err
	}

	return &MrtdPassword{password: pass}, nil
}

func NewPasswordMrzi(documentNo, dateOfBirth, dateOfExpiry string) (*MrtdPassword, error) {
	var err error
	var pass *password.Password

	pass, err = password.NewPasswordMrzi(documentNo, dateOfBirth, dateOfExpiry)
	if err != nil {
		return nil, err
	}

	return &MrtdPassword{password: pass}, nil
}

func NewPasswordCan(can string) (*MrtdPassword, error) {
	return &MrtdPassword{password: password.NewPasswordCan(can)}, nil
}

type Reader struct {
	status      ReaderStatus
	transceiver Transceiver
	maxRead     int
	skipPace    bool
	skipImages  bool
	aaChallenge []byte
}

type Document struct {
	documentEx *document.DocumentEx
}

func NewReader(status ReaderStatus, transceiver Transceiver) *Reader {
	var out Reader
	out.status = status
	out.transceiver = transceiver
	return &out
}

// sets the APDU Max LE (1..65536) (0 to disable override)
func (r *Reader) SetApduMaxLe(maxRead int) error {
	if maxRead < 0 || maxRead > 65536 {
		return fmt.Errorf("[SetApduMaxLe] maxRead must be 0 or between 1 and 65536")
	}
	r.maxRead = maxRead
	return nil
}

// SkipPace configures the reader to skip PACE during document reading
func (r *Reader) SkipPace() {
	r.skipPace = true
}

// SkipImages configures the reader to skip image data groups (DG2, DG7)
func (r *Reader) SkipImages() {
	r.skipImages = true
}

// WithAAChallenge sets a caller-supplied 8-byte RND.IFD challenge for Active
// Authentication. If not called, a random challenge is generated internally.
//
// Security-conscious callers should always supply their own challenge rather
// than relying on the internally generated random value. When the library
// generates the challenge it is ephemeral — if it is not captured and passed
// to the verifier, there is no way to confirm the AA response was generated
// for this specific session (relay-attack prevention). The recommended pattern:
//
//  1. Generate a cryptographically random 8-byte value.
//  2. Supply it here via WithAAChallenge before calling ReadDocument.
//  3. Pass the same value to Verifier.WithAAChallenge when verifying the
//     captured evidence; the verifier will hard-error on a nonce mismatch.
func (r *Reader) WithAAChallenge(challenge []byte) (*Reader, error) {
	if len(challenge) != 8 {
		return nil, fmt.Errorf("[WithAAChallenge] challenge must be exactly 8 bytes, got %d", len(challenge))
	}
	r.aaChallenge = bytes.Clone(challenge)
	return r, nil
}

func (r *Reader) ReadDocument(password *MrtdPassword, atr []byte, ats []byte) (doc *Document, err error) {
	defer func() {
		if e := recover(); e != nil {
			switch x := e.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("unknown panic")
			}
			debug.PrintStack()
		}
	}()

	doc = &Document{}

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(r.transceiver)

	if r.maxRead > 0 {
		nfc.SetMaxLe(r.maxRead)
	}

	certPool, err := getCscaCertPool()
	if err != nil {
		return nil, fmt.Errorf("[ReadDocument] getCscaCertPool error: %w", err)
	}

	var gmrtdReader *reader.Reader
	gmrtdReader = reader.NewReader(r.status, nfc, certPool)

	if r.skipPace {
		gmrtdReader.SkipPace()
	}

	if r.skipImages {
		gmrtdReader.SkipImages()
	}

	if r.aaChallenge != nil {
		if gmrtdReader, err = gmrtdReader.WithAAChallenge(r.aaChallenge); err != nil {
			return nil, fmt.Errorf("[ReadDocument] WithAAChallenge error: %w", err)
		}
	}

	doc.documentEx, err = gmrtdReader.ReadDocument(password.password, atr, ats)

	return doc, err
}

// CountryName returns the country name for an MRZ alpha-3 country code.
// Handles ICAO 9303 quirks such as Germany's special code "D" (mapped to "DEU").
func CountryName(mrzAlpha3 string) (string, error) {
	// special handling for Germany per ICAO9303p3 (5. CODES FOR NATIONALITY...)
	if mrzAlpha3 == "D" {
		mrzAlpha3 = "DEU"
	}

	country := iso3166.ByAlpha3(mrzAlpha3)
	if country == nil {
		return "", fmt.Errorf("[CountryName] unable to resolve alpha-3 country code (%s)", mrzAlpha3)
	}

	return country.Name, nil
}

// OidDesc returns the description associated with an OID string (e.g. "0.4.0.127.0.7").
// Returns an empty string if the OID is unknown.
func OidDesc(oidStr string) string {
	return oid.OidDescStr(oidStr)
}

type Verifier struct {
	aaChallenge []byte
}

func NewVerifier() *Verifier {
	return &Verifier{}
}

// WithAAChallenge sets a caller-supplied 8-byte challenge to bind against the
// AA evidence nonce during verification. Security-conscious callers should
// always supply their own challenge — this is what closes the relay-attack
// window. When set and AA evidence is present, Verify returns a hard error if
// the evidence nonce does not match the supplied challenge, or if the AA
// signature itself fails to verify. See Reader.WithAAChallenge for the
// corresponding read-side method.
func (v *Verifier) WithAAChallenge(challenge []byte) (*Verifier, error) {
	if len(challenge) != 8 {
		return nil, fmt.Errorf("[WithAAChallenge] challenge must be exactly 8 bytes, got %d", len(challenge))
	}
	v.aaChallenge = bytes.Clone(challenge)
	return v, nil
}

func (v *Verifier) Verify(data []byte) (doc *Document, err error) {
	certPool, err := getCscaCertPool()
	if err != nil {
		return nil, fmt.Errorf("[Verify] getCscaCertPool error: %w", err)
	}

	gmrtdVerifier := verifier.NewVerifier(certPool)

	if v.aaChallenge != nil {
		if gmrtdVerifier, err = gmrtdVerifier.WithAAChallenge(v.aaChallenge); err != nil {
			return nil, fmt.Errorf("[Verify] WithAAChallenge error: %w", err)
		}
	}

	docEx, err := gmrtdVerifier.Verify(data)
	if err != nil {
		return nil, fmt.Errorf("[Verify] verifier error: %w", err)
	}

	return &Document{documentEx: docEx}, nil
}

func (doc *Document) DocumentExJson() (jsonData []byte, err error) {
	if doc.documentEx == nil {
		return nil, fmt.Errorf("[DocumentJson] No document available")
	}

	jsonData, err = json.Marshal(doc.documentEx)

	return jsonData, err
}

func (doc *Document) DocumentExCbor() (cborData []byte, err error) {
	if doc.documentEx == nil {
		return nil, fmt.Errorf("[DocumentExCbor] No document available")
	}

	return doc.documentEx.ToCbor()
}
