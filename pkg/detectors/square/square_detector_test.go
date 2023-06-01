package square

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"token - valid", `sq0atp-12345\6789_abcde-VWXYZ`, true},
	{"token - missing prefix", `12345\6789_abcde-VWXYZ`, false},
	{"token - illegal prefix", `sq0xyz-12345\6789_abcde-VWXYZ`, false},
	{"token - secret prefix", `sq0csp-12345\6789_abcde-VWXYZ`, false},
	{"token - uppercase prefix", `SQ0ATP-12345\6789_abcde-VWXYZ`, false},
	{"token - missing separator", `sq0atp12345\6789_abcde-VWXYZ`, false},
	{"token - wrong separator", `sq0atp_12345\6789_abcde-VWXYZ`, false},
	{"token - missing suffix", `sq0atp`, false},
	{"token - illegal character suffix", `sq0atp-12345\6789_abcde-VWXY=`, false},
	{"token - suffix too long", `sq0atp-12345\6789_abcde-VWXYZa`, false},
	{"token - suffix too short", `sq0atp-12345\6789_abcde-VWXY`, false},

	{"secret - valid", `sq0csp-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, true},
	{"secret - missing prefix", `1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, false},
	{"secret - illegal prefix", `sq0xyz-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, false},
	{"secret - token prefix", `sq0atp-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, false},
	{"secret - uppercase prefix", `SQ0CSP-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, false},
	{"secret - missing separator", `sq0csp1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, false},
	{"secret - wrong separator", `sq0csp_1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_1234`, false},
	{"secret - missing suffix", `sq0csp`, false},
	{"secret - illegal character suffix", `sq0csp-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_123+`, false},
	{"secret - suffix too long", `sq0csp-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_12345`, false},
	{"secret - suffix too short", `sq0csp-1234567890\abcdefghijk-LMNOPQRSTUVWXYZ_123`, false},

	{"empty input", "", false},
}

var squareDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, squareDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, squareDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, squareDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, squareDetector, testCases)
}
