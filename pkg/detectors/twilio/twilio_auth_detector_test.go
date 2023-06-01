package twilio

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"account - lowercase", "AC1234567890abcdef1234567890abcdef", true},
	{"account - uppercase", "AC1234567890ABCDEF1234567890ABCDEF", true},
	{"account - missing prefix", "1234567890abcdef1234567890abcdef", false},
	{"account - illegal prefix", "MM1234567890abcdef1234567890abcdef", false},
	{"account - lowercase prefix", "ac1234567890abcdef1234567890abcdef", false},
	{"account - missing suffix", "AC", false},
	{"account - illegal characters suffix", "AC1234567890ghijkl1234567890ghijkl", false},
	{"account - suffix too long", "AC1234567890abcdef1234567890abcdefg", false},
	{"account - suffix too short", "AC1234567890abcdef1234567890abcde", false},

	{"key - lowercase", "SK1234567890abcdef1234567890abcdef", true},
	{"key - uppercase", "SK1234567890ABCDEF1234567890ABCDEF", true},
	{"key - lowercase prefix", "sk1234567890abcdef1234567890abcdef", false},
	{"key - missing suffix", "SK", false},
	{"key - illegal characters suffix", "SK1234567890ghijkl1234567890ghijkl", false},
	{"key - suffix too long", "SK1234567890abcdef1234567890abcdefg", false},
	{"key - suffix too short", "SK1234567890abcdef1234567890abcde", false},

	{"empty input", "", false},
}

var twilioDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, twilioDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, twilioDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, twilioDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, twilioDetector, testCases)
}
