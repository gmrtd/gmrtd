package iso19794

import (
	"bytes"
	_ "embed" // Import for loading test files
	"testing"

	"github.com/gmrtd/gmrtd/utils"
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

	images := data.Images()

	if len(images) != 1 {
		t.Fatalf("1 image expected")
	}

	// verify that the photo matches the reference data
	if !bytes.Equal(images[0], test1face) {
		t.Fatalf("photo differs to expected")
	}
}

//go:embed test_data/ISO19794_Test2_Data_InvalidImage.bin
var test2data []byte

func TestProcessISO19794InvalidImage(t *testing.T) {
	_, err := ProcessISO19794(test2data)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestProcessISO19794Permutations(t *testing.T) {
	// FacialHeader(valid)
	var facialHeaderValid []byte = utils.HexToBytes("4641430030313000000014190001")

	// FacialInfo(valid)
	var facialInfoValid []byte = utils.HexToBytes("0000140b00000000000000000000000000000000")

	// FacialFeature(valid)
	var facialFeatureValid []byte = utils.HexToBytes("0000000000000000")

	// ImageInfo(valid)
	var imageInfoValid []byte = utils.HexToBytes("020100940046000000000000")

	// Test cases for recordLength and dataLength differences
	testCases := []struct {
		name          string
		data          []byte
		modifyData    func([]byte) []byte
		expectError   bool
		errorContains string
	}{
		{
			name: "Invalid: Image is shorter than expected (by 1 byte)",
			data: test1data,
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// remove last byte (from image)
				testData = testData[:len(testData)-1]
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseImage] Image Size cannot be more than remaining data",
		},
		{
			name: "Valid: recordLength equals dataLength",
			data: test1data,
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
			data: test1data,
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
			data: test1data,
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
			data: test1data,
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
			data: test1data,
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
			data: test1data,
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
		{
			name: "Invalid: FacialHeader too short (1 byte less than expected)",
			data: facialHeaderValid,
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// reduce size by 1 byte to trigger parsing error for FacialHeader
				return testData[:len(testData)-1]
			},
			expectError:   true,
			errorContains: "[ProcessISO19794] binary.Read error: unexpected EOF",
		},
		{
			name: "Invalid: FacialHeader.FormatID differs to expected (0x46->0xff)",
			data: facialHeaderValid,
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// invalidate FacialHeader.FormatID
				testData[0] = 0xff
				return testData
			},
			expectError:   true,
			errorContains: "[ProcessISO19794] Invalid FacialHeader.FormatID",
		},
		{
			name: "Invalid: FacialHeader.NumberOfFaces too large (act:65535, max:4)",
			data: facialHeaderValid,
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// set NumberOfFaces to 0xffff (65535)
				testData[12] = 0xff
				testData[13] = 0xff
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "parseImages error: [parseImages] too many images",
		},
		{
			name: "Invalid: FacialInfo too short (1 byte less than expected)",
			data: append(facialHeaderValid, facialInfoValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// reduce size by 1 byte to trigger parsing error for FacialInfo
				testData = testData[:len(testData)-1]
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseImage] binary.Read(FacialInfo) error: unexpected EOF",
		},
		{
			name: "Invalid: FacialFeature present, but data after is missing (testing FacialFeature recording)",
			data: append(append(facialHeaderValid, facialInfoValid...), facialFeatureValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// indicate 1 FacialFeature present
				testData[14+4] = 0x00
				testData[14+5] = 0x01
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseImage] binary.Read(ImageInfo) error: EOF",
		},
		{
			name: "Invalid: FacialFeature present, but too many features advertised (act:65535, max:32)",
			data: append(append(facialHeaderValid, facialInfoValid...), facialFeatureValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// indicate 1 FacialFeature present
				testData[14+4] = 0xff
				testData[14+5] = 0xff
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseFeatures] too many facial-features",
		},
		{
			name: "Invalid: FacialFeature present, but less bytes than expected",
			data: append(append(facialHeaderValid, facialInfoValid...), facialFeatureValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// indicate 1 FacialFeature present
				testData[14+4] = 0x00
				testData[14+5] = 0x01
				// reduce size by 1 byte to trigger parsing error for FacialFeature
				testData = testData[:len(testData)-1]
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseFeatures] binary.Read(i:0) error: unexpected EOF",
		},
		{
			name: "Invalid: Missing ImageInfo",
			data: append(facialHeaderValid, facialInfoValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseImage] binary.Read(ImageInfo) error: EOF",
		},
		{
			name: "Invalid: Missing image",
			data: append(append(facialHeaderValid, facialInfoValid...), imageInfoValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseImage] Image Size cannot be more than remaining data",
		},
		{
			name: "Invalid: Malicious FacialInfo.Length (must be > 32 bytes)",
			data: append(append(facialHeaderValid, facialInfoValid...), imageInfoValid...),
			modifyData: func(data []byte) []byte {
				testData := bytes.Clone(data)
				// change FacialInfo.Length to < 32 (set to 31 -> 0x0000001F)
				testData[14] = 0x00
				testData[15] = 0x00
				testData[16] = 0x00
				testData[17] = 0x1F
				// update length
				dataLen := len(testData)
				testData[8] = byte(dataLen >> 24)
				testData[9] = byte(dataLen >> 16)
				testData[10] = byte(dataLen >> 8)
				testData[11] = byte(dataLen)
				return testData
			},
			expectError:   true,
			errorContains: "[parseImage] FacialInfo.Length smaller than allowed minimum",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testData := bytes.Clone(tc.data)

			if tc.modifyData != nil {
				testData = tc.modifyData(testData)
			}

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
