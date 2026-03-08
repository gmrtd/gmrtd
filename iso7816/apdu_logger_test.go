package iso7816

import (
	"bytes"
	"testing"
)

func TestApduLogger(t *testing.T) {

	// create log
	l := NewApduLog()

	// newly created log should have 0 entries
	if len(l.Entries) != 0 {
		t.Errorf("expected 0 entries")
	}

	// create new entry (without child)
	{
		preEntriesCnt := len(l.Entries)

		e := NewApduLogEntry("event 1", []byte{1, 2, 3})

		e.Finalise([]byte{4, 5, 6})

		// 2nd finalise should silently do nothing
		e.Finalise([]byte{7, 8, 9})

		if !bytes.Equal(e.Rx, []byte{4, 5, 6}) {
			t.Errorf("RX incorrect value")
		}

		l.Add(e)

		if len(l.Entries) != preEntriesCnt+1 {
			t.Errorf("expected 1 more entry")
		}
	}

	// create new entry (WITH child)
	{
		preEntriesCnt := len(l.Entries)

		e := NewApduLogEntry("event 2", []byte{1, 2, 3})

		e2 := NewApduLogEntry("event 2 - child", []byte{'a', 'b', 'c'})

		e.SetChild(e2)

		// setChild with nil record should silently ignore
		e.SetChild(nil)

		e.Finalise([]byte{4, 5, 6})

		l.Add(e)

		if len(l.Entries) != preEntriesCnt+1 {
			t.Errorf("expected 1 more entry")
		}
	}

	// adding nil entry should silently skip
	{
		preEntriesCnt := len(l.Entries)

		l.Add(nil)

		if len(l.Entries) != preEntriesCnt {
			t.Errorf("error")
		}
	}

	{
		expEntryCnt := 2

		all := l.AllEntries()

		if len(all) != expEntryCnt {
			t.Errorf("wrong number of entries (exp:%1d, act:%01d)", expEntryCnt, len(all))
		}
	}
}
