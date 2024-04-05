package gmrtd

func DoActiveAuth(nfc *NfcSession, doc *Document) {
	// active-authentication is only supported if DG15 is present
	if doc.Dg15 == nil {
		return
	}

	// TODO - NOT (YET) IMPLEMENTED
	//			- BSI doc indicates this can be inferred also from DG14 data

	return
}
