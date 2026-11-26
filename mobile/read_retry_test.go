package mobile_test

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/internal/testchip"
	"github.com/gmrtd/gmrtd/mobile"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
)

func TestMobileReadDocumentSucceedsAfterAccessFailure(t *testing.T) {
	sample, err := document.SampleDocument()
	if err != nil {
		t.Fatal(err)
	}
	const number, birth, expiry = "123456", "100101", "301225"
	credential, err := password.NewPasswordMrzi(number, birth, expiry)
	if err != nil {
		t.Fatal(err)
	}
	files := map[uint16][]byte{
		reader.MRTDFileIdEFSOD: sample.Mf.Lds1.Sod.RawData,
		reader.MRTDFileIdDG1:   sample.Mf.Lds1.Dg1.RawData,
	}
	r := mobile.NewReader(nil, testchip.NewBAC(t, credential, &testchip.Files{ByID: files}))
	can, err := mobile.NewPasswordCan("123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadDocument(can, nil, nil); err == nil || r.LastReadError() != mobile.READ_ERROR_NO_SECURE_MESSAGING {
		t.Fatalf("expected CAN read to fail without PACE, got %v, kind %d", err, r.LastReadError())
	}
	mrz, err := mobile.NewPasswordMrzi(number, birth, expiry)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := r.ReadDocument(mrz, nil, nil)
	if err != nil || doc == nil {
		t.Fatalf("expected successful BAC read, got %v", err)
	}
	if r.LastReadError() != mobile.READ_ERROR_NONE || r.RejectedDocument() != nil {
		t.Fatal("successful read retained a failed read state")
	}
	encoded, err := doc.DocumentExCbor()
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := document.UnmarshalVerifiableDoc(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Mf.Lds1.Dg1 == nil || !bytes.Equal(decoded.Mf.Lds1.Dg1.RawData, sample.Mf.Lds1.Dg1.RawData) {
		t.Fatal("exported document does not contain the DG1 read from the chip")
	}
}
