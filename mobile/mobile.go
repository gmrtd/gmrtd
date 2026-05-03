package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
)

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

func cscaMasterList() (cms.CertPool, error) {
	var cscaCertPool cms.CertPool
	var err error

	cscaCertPool, err = cms.DefaultMasterList()
	if err != nil {
		return nil, fmt.Errorf("[cscaMasterList] cms.DefaultMasterList error: %w", err)
	}

	return cscaCertPool, nil
}

// reads the document (and performs passive authentication)
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

	cscaMasterList, err := cscaMasterList()
	if err != nil {
		return nil, fmt.Errorf("[ReadDocument] cscaMasterList error: %w", err)
	}

	var gmrtdReader *reader.Reader
	gmrtdReader = reader.NewReader(r.status, nfc, cscaMasterList)

	// read (and verify) the document (inc passive-authentication)
	doc.documentEx, err = gmrtdReader.ReadDocument(password.password, atr, ats)

	return doc, err
}

func (doc *Document) DocumentExJson() (jsonData []byte, err error) {
	if doc.documentEx == nil {
		return nil, fmt.Errorf("[DocumentJson] No document available")
	}

	jsonData, err = json.Marshal(doc.documentEx)

	return jsonData, err
}
