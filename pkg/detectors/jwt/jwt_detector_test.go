package jwt

import (
	"testing"

	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"valid jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},
	{"valid jwt but have leading characters", "XeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
	{"valid jwt but have trailing characters", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c&", false},
	{"valid jwt - but header contains CR/LF-s", "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", true},
	{"valid jwt - but claims contain bunch of LF newlines", "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJuYW1lIjoiSm9lIiwKInN0YXR1cyI6ImVtcGxveWVlIgp9", true},
	{"valid jwt - claims contain strings with unicode accents", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IsWww6HFkcOtIMOWxZHDqcOoIiwiaWF0IjoxNTE2MjM5MDIyfQ.k5HibI_uLn_RTuPcaCNkaVaQH2y5q6GvJg8GPpGMRwQ", true},
	{"decoded - invalid", `{"alg":"HS256","typ":"JWT"}.{"name":"Jon Doe"}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`, false},
	{"invalid json - invalid (caught by regex)", "bm90X3ZhbGlkX2pzb25fYXRfYWxs.bm90X3ZhbGlkX2pzb25fYXRfYWxs.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
	{"missing claims - invalid", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", false},
	{"totally not a jwt", "jwt", false},
	{"invalid json with random bytes", "eyJhbasdGciOiJIUaddasdasfsasdasdzI1NiIasdsInR5cCI6IkpXVCasdJasd9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
	{"invalid json in jwt header - invalid (caught by parsing)", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
	{"passes regex (without signature), but otherwise totally not JWT", "eyJAAAA.eyJBBB", false},
	{"passes regex, but otherwise totally not JWT", "eyJBB.eyJCC.eyJDDDD", false},
	{"empty input", "", false},
}

var jwtDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, jwtDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, jwtDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, jwtDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, jwtDetector, testCases)
}
