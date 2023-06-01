package mailchimp

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"valid key - min length", "1234567890abcdef1234567890abcdef-us1", true},
	{"valid key - max length", "1234567890abcdef1234567890abcdef-us99", true},

	{"missing prefix", "us99", false},
	{"illegal characters prefix", "1234567890uvwxyz1234567890uvwxyz-us1", false},
	{"illegal uppercase prefix", "1234567890ABCDEF1234567890ABCDEF-us1", false},
	{"too long prefix", "1234567890abcdef1234567890abcdef1-us1", false},
	{"too short prefix", "1234567890abcdef1234567890abcde-us1", false},

	{"illegal separator", "1234567890abcdef1234567890abcdef_us1", false},
	{"missing separator", "1234567890abcdef1234567890abcdefus1", false},

	{"missing suffix", "1234567890abcdef1234567890abcdef", false},
	{"illegal suffix", "1234567890abcdef1234567890abcdef-uk1", false},
	{"illegal uppercase suffix", "1234567890abcdef1234567890abcdef-US1", false},
	{"too long suffix", "1234567890abcdef1234567890abcdef-us123", false},
	{"too short suffix", "1234567890abcdef1234567890abcdef-us", false},

	{"empty input", "", false},
}

var mailchimpDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, mailchimpDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, mailchimpDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, mailchimpDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, mailchimpDetector, testCases)
}
