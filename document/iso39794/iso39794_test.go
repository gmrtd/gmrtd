package iso39794

import "testing"

func TestProcessISO39794_5_AP_BadData(t *testing.T) {
	var badData []byte = []byte{0xA1, 0x12, 0x12, 0x34}

	_, err := ProcessISO39794_5_AP(badData)
	if err == nil {
		t.Fatalf("Error Expected")
	}
}

func TestProcessISO39794_5_AP_NilData(t *testing.T) {
	_, err := ProcessISO39794_5_AP(nil)
	if err == nil {
		t.Fatalf("Error Expected")
	}
}
