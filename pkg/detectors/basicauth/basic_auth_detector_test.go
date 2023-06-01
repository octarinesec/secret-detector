package basicauth

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	// Shortest possible auth is ":" -> to base64 without padding
	{"valid token - minimal length", "basic Og", true},
	{"valid token - minimal length with padding", "basic Og==", true},
	{"valid token - long", "Basic ABCDEFGHIJ+KLMNOPQRST/UVWXYZ,abcdefghij_klmnopqrstuvwxyz-1234567890==", true},
	{"valid token - with header key", "Authorization: Basic dXNlcjpwd2Q=", true},
	{"valid token - with quoted header key", `"Authorization": "Basic dXNlcjpwd2Q="`, true},
	{"valid token - single padding", "BASIC  YWRtaW46YWRtaW4=", true},

	{"token too short", "basic O", false},
	{"token too short with padding", "basic O==", false},
	{"missing basic auth scheme", "YWRtaW46YWRtaW4=", false},
	{"wrong auth scheme", "bearer YWRtaW46YWRtaW4=", false},
	{"illegal padding position", "basic xy=z", false},
	{"illegal characters", "basic xy.z", false},
	{"empty input", "", false},
}

var basicAuthDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, basicAuthDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, basicAuthDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, basicAuthDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, basicAuthDetector, testCases)
}
