package basicauth

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	// Shortest possible auth is ":" -> to base64 without padding
	{"valid token - minimal length", "basic dTpw", true},
	{"valid token - with padding", "basic ZDp6cg==", true},
	{"valid token - long", "Basic dXNlcm5mc2RzZ2dmc2dzZmdzZmFtZTpwZ3NzZmdzZ3Nnc2RndGFlZ2FnYXNzd29yZGRkZGQ=", true},
	{"valid token - with header key", "Authorization: Basic YTpn", true},
	{"valid token - with quoted header key", `"Authorization": "Basic YTpn"`, true},

	{"invalid token - minimal length with invalid base 64", "basic Og=", false},
	{"invalid token - without padding", "basic ZDp6cg", false},
	{"invalid token - without : inside the base64", "basic YWRkc2Y6", false},
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
