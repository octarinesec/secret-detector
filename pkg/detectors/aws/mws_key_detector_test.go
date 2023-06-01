package aws

import (
	"crypto/rand"
	"fmt"
	"testing"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
)

var mwsKeyTestCases = []tests.TestCase{

	{"valid key - all digits", "amzn.mws.12345678-1234-1234-1234-123456789012", true},
	{"valid key - all letters", "amzn.mws.abcdefab-abcd-abcd-abcd-abcdefabcdef", true},
	{"valid key - random", "amzn.mws." + generateRandomUUID(), true},

	{"missing prefix", "12345678-1234-1234-1234-123456789012", false},
	{"illegal prefix", "mws.12345678-1234-1234-1234-123456789012", false},
	{"uppercase prefix", "AMZN.MWS.12345678-1234-1234-1234-123456789012", false},

	{"missing suffix", "amzn.mws", false},
	{"illegal characters suffix", "amzn.mws.abcdefgh-abcd-abcd-abcd-abcdefabcdef", false},
	{"uppercase characters suffix", "amzn.mws.ABCDEFAB-ABCD-ABCD-ABCD-ABCDEFABCDEF", false},
	{"suffix too long", "amzn.mws.abcdefab-abcd-abcd-abcd-abcdefabcdefa", false},
	{"suffix too short", "amzn.mws.abcdefab-abcd-abcd-abcd-abcdefabcde", false},
	{"suffix missing separators", "amzn.mws.abcdefababcdabcdabcdabcdefabcdef", false},
	{"empty input", "", false},
}

var mwsDetector = NewMWSKeyDetector()

func TestMWSKeyDetector_Scan(t *testing.T) {
	tests.TestScan(t, mwsDetector, mwsKeyTestCases)
}

func TestMWSKeyDetector_ScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, mwsDetector, mwsKeyTestCases)
}

func TestMWSKeyDetector_ScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, mwsDetector, mwsKeyTestCases)
}

func TestMWSKeyDetector_ScanMap(t *testing.T) {
	tests.TestScanMap(t, mwsDetector, mwsKeyTestCases)
}

func generateRandomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("this shouldn't happen")
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])

}
