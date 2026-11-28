package mobile_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/internal/testchip"
	"github.com/gmrtd/gmrtd/mobile"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/reader"
)

func newSampleBACReader(t *testing.T, dg2 []byte) (*mobile.Reader, *mobile.MrtdPassword, *document.Document) {
	t.Helper()
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
	if dg2 != nil {
		files[reader.MRTDFileIdDG2] = dg2
	}
	r := mobile.NewReader(nil, testchip.NewBAC(t, credential, &testchip.Files{ByID: files}))
	mrz, err := mobile.NewPasswordMrzi(number, birth, expiry)
	if err != nil {
		t.Fatal(err)
	}
	return r, mrz, sample
}

func TestMobileReadDocumentSucceedsAfterAccessFailure(t *testing.T) {
	r, mrz, sample := newSampleBACReader(t, nil)
	can, err := mobile.NewPasswordCan("123456")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadDocument(can, nil, nil); err == nil || r.LastReadError() != mobile.READ_ERROR_NO_SECURE_MESSAGING {
		t.Fatalf("expected CAN read to fail without PACE, got %v, kind %d", err, r.LastReadError())
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

func TestMobileRequireAuthenticDocumentReturnsRejectedRead(t *testing.T) {
	r, mrz, _ := newSampleBACReader(t, nil)
	r.RequireAuthenticDocument()
	doc, err := r.ReadDocument(mrz, nil, nil)
	if !errors.Is(err, reader.ErrDocumentNotAuthentic) || r.LastReadError() != mobile.READ_ERROR_DOCUMENT_NOT_AUTHENTIC {
		t.Fatalf("expected authenticity rejection, got %v (kind %d)", err, r.LastReadError())
	}
	rejected := r.RejectedDocument()
	if rejected == nil || doc != rejected {
		t.Fatal("expected the completed read as the rejected document")
	}
	raw, err := rejected.SummaryJson()
	if err != nil {
		t.Fatal(err)
	}
	var summary document.DocumentSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.DataTrusted || summary.PassiveAuth == nil || summary.PassiveAuth.Status != document.PASSIVE_AUTH_STATUS_FAILED {
		t.Fatal("rejected document should report untrusted data and failed passive authentication")
	}
}

func TestMobileReadDocumentRetainsDG1AfterDG2Fails(t *testing.T) {
	r, mrz, sample := newSampleBACReader(t, []byte{0x75, 0x02, 0x5c, 0x00})
	doc, err := r.ReadDocument(mrz, nil, nil)
	if doc == nil || err == nil || !strings.Contains(err.Error(), "Parse DG(fileId:2)") {
		t.Fatalf("expected partial document and DG2 parse error, got document present=%t, err=%v", doc != nil, err)
	}
	if r.LastReadError() != mobile.READ_ERROR_OTHER || r.RejectedDocument() != nil {
		t.Fatalf("unexpected classification for partial read: kind=%d, rejected=%t", r.LastReadError(), r.RejectedDocument() != nil)
	}
	encoded, err := doc.DocumentExCbor()
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := document.UnmarshalVerifiableDoc(encoded)
	if err != nil {
		t.Fatal(err)
	}
	lds := decoded.Mf.Lds1
	if lds.Dg1 == nil || !bytes.Equal(lds.Dg1.RawData, sample.Mf.Lds1.Dg1.RawData) || lds.Dg2 != nil {
		t.Fatal("expected partial export to retain DG1 and omit DG2")
	}
	raw, err := doc.SummaryJson()
	if err != nil {
		t.Fatal(err)
	}
	var summary document.DocumentSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.DataTrusted || summary.PassiveAuth == nil || summary.PassiveAuth.Status != document.PASSIVE_AUTH_STATUS_NOT_PERFORMED {
		t.Fatal("expected untrusted data and no passive authentication on a partial read")
	}
}
