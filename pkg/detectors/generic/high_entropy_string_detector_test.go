package generic

import (
	"github.com/stretchr/testify/assert"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
	"testing"
)

var highEntropyTestCases = []tests.TestCase{
	{"hex - short high entropy", "1234567890abcdef", true},
	{"hex - long high entropy", "9a3aff9be15b2f98039f0de2883eb7936d50a97b48d78dbc1d47d6ecaa243889", true},

	{"hex - entropy exactly on threshold", "abcdef12abcdef12", false},
	{"hex - low entropy", "abcdabcdabcdabcd", false},
	{"hex - too short", "1234567890abcde", false},

	{"base64 - std encoding short high entropy", "QRSTU+vwxyz/123456", true},
	{"base64 - url encoding short high entropy", "QRSTU_vwxyz-123456", true},
	{"base64 - long high entropy", "dGhpcyBpcyBhIHRlc3QgZm9yIGhpZ2ggZW50cm9weSBiYXNlNjQgc2VjcmV0IGRldGVjdGlvbg==", true},

	{"base64 - entropy exactly on threshold", "QRSTUvwxyz123456", false},
	{"base64 - low entropy", "QRSTUvwxyz12345=", false},
	{"base64 - too short", "dG9vX3Nob3J0IQ==", false},

	{"number", "1234567890987654321", false},
	{"illegal characters", "123456789=abcdef", false},
	{"empty input", "", false},
}

var highEntropyStrDetector = NewHighEntropyStringDetector()

func TestHighEntropyStringDetector_Scan(t *testing.T) {
	tests.TestScan(t, highEntropyStrDetector, highEntropyTestCases)
}

func TestHighEntropyStringDetector_ScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, highEntropyStrDetector, highEntropyTestCases)
}

func TestHighEntropyStringDetector_ScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, highEntropyStrDetector, highEntropyTestCases)
}

func TestHighEntropyStringDetector_ScanMap(t *testing.T) {
	tests.TestScanMap(t, highEntropyStrDetector, highEntropyTestCases)
}

func TestCalcShannonEntropy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"all characters similar", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0},
		{"two characters equal frequency", "xxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyy", 1},
		{"four characters equal frequency", "abcdabcdabcdabcdabcdabcdabcdabcd", 2},
		{"eight characters equal frequency", "1234567887654321", 3},
		{"16 characters equal frequency", "abc1234567890deffed0987654321cba", 4},
		{"quarter-quarter-half frequencies", "xxyyzzzz", 1.5},
		{"empty input", "", 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := calcShannonEntropy(test.input)
			assert.Equal(t, test.expected, actual)
		})
	}
}
