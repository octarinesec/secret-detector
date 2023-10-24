package bearerauth

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"valid token - minimal length", "bearer xx", true},
	{"valid token - with header key", "Authorization: Bearer dG9wX3NlY3JldA==", true},
	{"valid token - with quoted header key", `"Authorization": "Bearer dG9wX3NlY3JldA=="`, true},
	{"valid token - long", "Bearer  ABCDEFGHIJ+KLMNOPQRST/UVWXYZ,abcdefghij_klmnopq.rstuvwxyz-1234567890==", true},
	{"valid token", "headers = {\"Authorization\": \"Bearer aoekthaoexukatoehsxkth8324AOX\"}", true},

	{"invalid token - without bearer", "headers = {\"Authorization\": \"aoekthaoexukatoehsxkth8324AOX\"}", false},
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
