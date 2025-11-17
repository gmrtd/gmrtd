package iso19794

import (
	"bytes"
	_ "embed"
	"testing"
)

//go:embed test_data/ISO19794_Test1_Data.bin
var test1data []byte

//go:embed test_data/ISO19794_Test1_Face.jpg
var test1face []byte

func TestProcessISO19794(t *testing.T) {
	data, err := ProcessISO19794(test1data)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	images := data.GetImages()

	if len(images) != 1 {
		t.Fatalf("1 image expected")
	}

	// verify that the photo matches the reference data
	if !bytes.Equal(images[0], test1face) {
		t.Fatalf("photo differs to expected")
	}
}

func TestProcessISO19794RecordLengthValidation(t *testing.T) {
	// Test cases for recordLength and dataLength differences
	testCases := []struct {
		name          string
		modifyData    func([]byte) []byte
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid: recordLength equals dataLength",
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// recordLength is at bytes 8-11 (uint32, big endian)
				dataLen := uint32(len(testData))
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError: false,
		},
		{
			name: "Valid: recordLength is dataLength - 1",
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// Set recordLength to dataLength - 1
				dataLen := uint32(len(testData)) - 1
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError: false,
		},
		{
			name: "Valid: recordLength is dataLength - 8",
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// Set recordLength to dataLength - 8
				dataLen := uint32(len(testData)) - 8
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError: false,
		},
		{
			name: "Invalid: recordLength is dataLength - 9",
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// Set recordLength to dataLength - 9 (exceeds tolerance)
				dataLen := uint32(len(testData)) - 9
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "FacialHeader.RecordLength does not match with data",
		},
		{
			name: "Invalid: recordLength is greater than dataLength",
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// Set recordLength to dataLength + 1
				dataLen := uint32(len(testData)) + 1
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "FacialHeader.RecordLength does not match with data",
		},
		{
			name: "Invalid: recordLength is dataLength + 10",
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// Set recordLength to dataLength + 10
				dataLen := uint32(len(testData)) + 10
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "FacialHeader.RecordLength does not match with data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testData := tc.modifyData(test1data)
			_, err := ProcessISO19794(testData)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tc.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tc.errorContains)) {
					t.Errorf("Expected error to contain '%s', got: %s", tc.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %s", err)
				}
			}
		})
	}
}

func TestProcessISO19794TooMuchDataRemaining(t *testing.T) {
	// Create test data with 10 extra bytes appended
	testData := bytes.Clone(test1data)
	extraData := make([]byte, 10)
	for i := range extraData {
		extraData[i] = 0xFF
	}
	testData = append(testData, extraData...)

	// Update the recordLength in the header to match the new data length
	// This ensures we pass the initial recordLength check and reach the
	// "too much data remaining" validation
	dataLen := uint32(len(testData))
	testData[8] = byte(dataLen >> 24)
	testData[9] = byte(dataLen >> 16)
	testData[10] = byte(dataLen >> 8)
	testData[11] = byte(dataLen)

	_, err := ProcessISO19794(testData)

	if err == nil {
		t.Errorf("Expected error but got nil")
	}

	if !bytes.Contains([]byte(err.Error()), []byte("Too much data remaining")) {
		t.Errorf("Expected error to contain 'Too much data remaining', got: %s", err.Error())
	}
}
