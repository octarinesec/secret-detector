package bearerauth

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"valid token - minimal length", "bearer dTpw", true},
	{"valid token - minimal length without padding", "bearer dTpw\"", true},
	{"valid token - with header key", "Authorization: Bearer ZDp6cg==", true},
	{"valid token - with quoted header key", `"Authorization": "Bearer YTpn"`, true},
	{"valid token - long", "Bearer  dXNlcm5mc2RzZ2dmc2dzZmdzZmFtZTpwZ3NzZmdzZ3Nnc2RndGFlZ2FnYXNzd29yZGRkZGQ=", true},
	{"valid token - with authorization", "\"Authorization\": \"Bearer YTpn\"", true},

	{"invalid token - minimal length with invalid base 64", "bearer  Og=", false},
	{"invalid token - without bearer", "headers = {\"Authorization\": \"aGkgeW8=\"}", false},
	{"invalid token - test token", " headers = {\"Authorization\": \"Bearer test\"}", false},
	{"false positive", "TIPC_NL_BEARER_DISABLE", false},
	{"false positive 2", "TIPC_NL_BEARER_GET", false},
	{"token too short", "bearer x", false},
	{"missing bearer auth scheme", "ABCDEFGHIJ", false},
	{"wrong auth scheme", "basic abcdefghij", false},
	{"illegal characters", "bearer ABCDEFGHIJ&", false},
	{"empty input", "", false},
}

var bearerAuthDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, bearerAuthDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, bearerAuthDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, bearerAuthDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, bearerAuthDetector, testCases)
}
