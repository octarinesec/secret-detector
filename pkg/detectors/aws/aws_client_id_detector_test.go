package aws

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var clientIdTestCases = []tests.TestCase{

	{"A3T prefix+letter", "A3TX1234567890ABCDEF", true},
	{"A3T prefix+digit", "A3T11234567890ABCDEF", true},
	{"AKIA prefix", "AKIA1234567890ABCDEF", true},
	{"AGPA prefix", "AGPA1234567890ABCDEF", true},
	{"AIDA prefix", "AIDA1234567890ABCDEF", true},
	{"AROA prefix", "AROA1234567890ABCDEF", true},
	{"AIPA prefix", "AIPA1234567890ABCDEF", true},
	{"ANPA prefix", "ANPA1234567890ABCDEF", true},
	{"ANVA prefix", "ANVA1234567890ABCDEF", true},
	{"ASIA prefix", "ASIA1234567890ABCDEF", true},

	{"missing prefix", "1234567890ABCDEF", false},
	{"illegal prefix", "AMBA1234567890ABCDEF", false},
	{"lowercase prefix", "akia1234567890ABCDEF", false},

	{"missing suffix", "AKIA", false},
	{"illegal characters suffix", "AKIA123456789+ABCDEF", false},
	{"lowercase characters suffix", "AKIA1234567890abcdef", false},
	{"suffix too long", "AKIA1234567890ABCDEFG", false},
	{"suffix too short", "AKIA1234567890ABCDE", false},
	{"empty input", "", false},
}

var clientIdDetector = NewClientIdDetector()

func TestClientIdDetector_Scan(t *testing.T) {
	tests.TestScan(t, clientIdDetector, clientIdTestCases)
}

func TestClientIdDetector_ScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, clientIdDetector, clientIdTestCases)
}

func TestClientIdDetector_ScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, clientIdDetector, clientIdTestCases)
}

func TestClientIdDetector_ScanMap(t *testing.T) {
	tests.TestScanMap(t, clientIdDetector, clientIdTestCases)
}
