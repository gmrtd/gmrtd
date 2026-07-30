package reader

import "fmt"

// StatusPhase identifies the stage of a document read that a status update refers to.
//
// The phases mirror the states of the Dart reader state-machine in
// privacybydesign/vcmrtd (lib/src/document_reader.dart), which is the reference for
// the distinctions a host application needs in order to drive a progress interface.
// Phases the Dart machine owns rather than the engine (NFC availability, pending,
// cancelling, cancelled, failed) are deliberately absent: the engine never reaches
// them, and a read that fails reports the failure through the returned error.
//
// A phase says which step the read has entered, not that the step found anything to
// do. STATUS_PHASE_ACTIVE_AUTHENTICATION and STATUS_PHASE_CHIP_AUTHENTICATION are
// both reported before the engine knows whether the document supports either
// protocol (DG15 and DG14 respectively), so they are reported even for a document
// that supports neither. A host that needs to know what actually ran should read the
// session results after the read rather than infer it from the phases.
type StatusPhase int

// intentionally use explicit values instead of iota, so the numbers stay stable
// for hosts that receive them across the mobile binding (see mobile.ReaderStatus)
const (
	STATUS_PHASE_CONNECTING              = 1  // first exchange with the chip (SELECT MF)
	STATUS_PHASE_READING_CARD_ACCESS     = 2  // EF.CardAccess
	STATUS_PHASE_ACCESS_CONTROL_PACE     = 3  // PACE
	STATUS_PHASE_ACCESS_CONTROL_BAC      = 4  // BAC (only attempted if PACE did not establish secure messaging)
	STATUS_PHASE_READING_DIR             = 5  // EF.DIR
	STATUS_PHASE_READING_SECURITY_OBJECT = 6  // EF.SOD
	STATUS_PHASE_READING_COMMON_DATA     = 7  // EF.COM
	STATUS_PHASE_READING_DATA_GROUP      = 8  // an LDS1 data-group, identified by Status.DataGroup
	STATUS_PHASE_ACTIVE_AUTHENTICATION   = 9  // AA
	STATUS_PHASE_CHIP_AUTHENTICATION     = 10 // CA (only attempted if chip authentication has not already completed)
	STATUS_PHASE_VERIFYING_DOCUMENT      = 11
	STATUS_PHASE_PASSIVE_AUTHENTICATION  = 12
	STATUS_PHASE_FINISHED                = 13 // the read completed
)

func (phase StatusPhase) String() string {
	switch phase {
	case STATUS_PHASE_CONNECTING:
		return "Connecting"
	case STATUS_PHASE_READING_CARD_ACCESS:
		return "Reading EF.CardAccess"
	case STATUS_PHASE_ACCESS_CONTROL_PACE:
		return "PACE"
	case STATUS_PHASE_ACCESS_CONTROL_BAC:
		return "BAC"
	case STATUS_PHASE_READING_DIR:
		return "Reading EF.DIR"
	case STATUS_PHASE_READING_SECURITY_OBJECT:
		return "Reading EF.SOD"
	case STATUS_PHASE_READING_COMMON_DATA:
		return "Reading EF.COM"
	case STATUS_PHASE_READING_DATA_GROUP:
		return "Reading DG"
	case STATUS_PHASE_ACTIVE_AUTHENTICATION:
		return "Active Authentication"
	case STATUS_PHASE_CHIP_AUTHENTICATION:
		return "Chip Authentication"
	case STATUS_PHASE_VERIFYING_DOCUMENT:
		return "Verifying Document"
	case STATUS_PHASE_PASSIVE_AUTHENTICATION:
		return "Passive Authentication"
	case STATUS_PHASE_FINISHED:
		return "Finished"
	}

	return fmt.Sprintf("*UnsupportedValue* (phase:%d)", int(phase))
}

// Status is a single progress update emitted during a document read.
type Status struct {
	Phase StatusPhase

	// DataGroup is the LDS1 data-group number (1..16) being read. It is only set
	// for STATUS_PHASE_READING_DATA_GROUP, and 0 for every other phase.
	DataGroup int
}

// String describes the status in English. It exists for logs and for the CLI -
// a host application should switch on Phase (and DataGroup) instead, as this text
// is not localised and not part of the contract.
func (status Status) String() string {
	if status.Phase == STATUS_PHASE_READING_DATA_GROUP {
		return fmt.Sprintf("Reading DG%02d", status.DataGroup)
	}

	return status.Phase.String()
}

// ReaderStatus receives progress updates while a document is being read.
type ReaderStatus interface {
	Status(status Status)
}

// reportPhase emits a status update for a phase that carries no data-group.
func (reader *Reader) reportPhase(phase StatusPhase) {
	reader.report(Status{Phase: phase})
}

// reportDataGroup emits a status update for the data-group currently being read.
func (reader *Reader) reportDataGroup(dataGroup int) {
	reader.report(Status{Phase: STATUS_PHASE_READING_DATA_GROUP, DataGroup: dataGroup})
}

// report passes a status update on, if a ReaderStatus was provided.
// NB a nil ReaderStatus is tolerated because the first update is emitted by the very
// first read step, so without this a caller that passes nil panics before the read
// can report the error it actually failed on.
func (reader *Reader) report(status Status) {
	if reader.status == nil {
		return
	}

	reader.status.Status(status)
}
