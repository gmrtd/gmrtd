package mobile

import (
	"encoding/json"
	"errors"
	"runtime/debug"

	"github.com/gmrtd/gmrtd/document"
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

type Password struct {
	password *password.Password
}

func NewPasswordMrz(mrz string) (*Password, error) {
	var err error
	var pass *password.Password

	pass, err = password.NewPasswordMrz(mrz)
	if err != nil {
		return nil, err
	}

	return &Password{password: pass}, nil
}

func NewPasswordMrzi(documentNo string, dateOfBirth string, dateOfExpiry string) (*Password, error) {
	var err error
	var pass *password.Password

	pass, err = password.NewPasswordMrzi(documentNo, dateOfBirth, dateOfExpiry)
	if err != nil {
		return nil, err
	}

	return &Password{password: pass}, nil
}

func NewPasswordCan(can string) (*Password, error) {
	return &Password{password: password.NewPasswordCan(can)}, nil
}

type Reader struct {
	gmrtdReader *reader.Reader
	document    *document.Document
}

func NewReader(status ReaderStatus) *Reader {
	var out Reader
	out.gmrtdReader = reader.NewReader(status)
	return &out
}

// sets the APDU Max LE (1..65536) (0 to disable override)
func (reader *Reader) SetApduMaxLe(maxRead int) error {
	reader.gmrtdReader.SetApduMaxLe(maxRead)
	return nil
}

// reads the document (and performs passive authentication)
func (reader *Reader) ReadDocument(transceiver Transceiver, password *Password, atr []byte, ats []byte) (jsonData []byte, err error) {
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

	// reset document (if already set)
	reader.document = nil

	// read (and verify) the document (inc passive-authentication)
	reader.document, err = reader.gmrtdReader.ReadDocument(transceiver, password.password, atr, ats)
	// NB proceed even if error, as we still want to return the document

	// generate JSON
	if reader.document != nil {
		// NB skip error check to avoid over-writing any earlier error
		jsonData, _ = json.Marshal(reader.document)
	}

	return jsonData, err
}
