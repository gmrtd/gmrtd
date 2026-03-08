package iso7816

import (
	"bytes"
	"time"
)

type ApduLog struct {
	Entries []*ApduLogEntry `json:"entries,omitempty"`
}

type ApduLogEntry struct {
	Desc      string        `json:"desc,omitempty"`
	Tx        []byte        `json:"tx,omitempty"`
	Rx        []byte        `json:"rx,omitempty"`
	Child     *ApduLogEntry `json:"child,omitempty"`
	DurMs     int64         `json:"durMs,omitempty"`
	StartTime time.Time     `json:"startTime"`

	finalised bool
}

func NewApduLog() *ApduLog {
	return &ApduLog{}
}

func NewApduLogEntry(desc string, tx []byte) *ApduLogEntry {
	return &ApduLogEntry{
		Desc:      desc,
		Tx:        bytes.Clone(tx),
		StartTime: time.Now(),
	}
}

func (e *ApduLogEntry) Finalise(rx []byte) {
	if e.finalised {
		return
	}

	e.DurMs = time.Since(e.StartTime).Milliseconds()
	e.Rx = bytes.Clone(rx)
	e.finalised = true
}

func (e *ApduLogEntry) SetChild(child *ApduLogEntry) {
	if child == nil {
		return
	}

	e.Child = child
}

func (l *ApduLog) Add(entry *ApduLogEntry) {
	if entry == nil {
		return
	}

	l.Entries = append(l.Entries, entry)
}

func (l *ApduLog) AllEntries() []*ApduLogEntry {
	return l.Entries
}
