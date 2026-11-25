package iso7816

import (
	"bytes"
	"time"
)

// ApduLog records the APDUs exchanged during an NFC session, in the order they were sent.
// It is not safe for concurrent use.
type ApduLog struct {
	Entries []*ApduLogEntry `json:"entries,omitempty"`
}

// ApduLogEntry is one APDU exchange: the encoded C-APDU (Tx), the R-APDU (Rx) and the time
// taken. When secure messaging is active, Tx and Rx hold the plain APDUs and Child holds the
// protected APDUs actually sent to and received from the chip.
type ApduLogEntry struct {
	Desc      string        `json:"desc,omitempty"`
	Tx        []byte        `json:"tx,omitempty"`
	Rx        []byte        `json:"rx,omitempty"`
	Child     *ApduLogEntry `json:"child,omitempty"`
	DurMs     int64         `json:"durMs,omitempty"`
	StartTime time.Time     `json:"startTime"`

	finalised bool
}

// NewApduLog returns an empty ApduLog.
func NewApduLog() *ApduLog {
	return &ApduLog{}
}

// NewApduLogEntry returns an entry for a C-APDU about to be sent, holding a copy of tx and
// the current time as its start time.
func NewApduLogEntry(desc string, tx []byte) *ApduLogEntry {
	return &ApduLogEntry{
		Desc:      desc,
		Tx:        bytes.Clone(tx),
		StartTime: time.Now(),
	}
}

// Finalise stores a copy of the R-APDU and the elapsed time since the entry was created.
// Only the first call has any effect.
func (e *ApduLogEntry) Finalise(rx []byte) {
	if e.finalised {
		return
	}

	e.DurMs = time.Since(e.StartTime).Milliseconds()
	e.Rx = bytes.Clone(rx)
	e.finalised = true
}

// SetChild sets the entry's child entry. A nil child is ignored.
func (e *ApduLogEntry) SetChild(child *ApduLogEntry) {
	if child == nil {
		return
	}

	e.Child = child
}

// Add appends entry to the log. A nil entry is ignored.
func (l *ApduLog) Add(entry *ApduLogEntry) {
	if entry == nil {
		return
	}

	l.Entries = append(l.Entries, entry)
}

// AllEntries returns the logged entries in order. The returned slice is not a copy.
func (l *ApduLog) AllEntries() []*ApduLogEntry {
	return l.Entries
}
