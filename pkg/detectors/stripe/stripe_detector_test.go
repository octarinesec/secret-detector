package stripe

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"standard - valid live", `sk_live_1234567890abcdefgHIJKLMN`, true},
	{"standard - valid test", `sk_test_1234567890abcdefgHIJKLMN`, true},
	{"standard - missing prefix", `1234567890abcdefgHIJKLMN`, false},
	{"standard - partial prefix", `live_1234567890abcdefgHIJKLMN`, false},
	{"standard - illegal prefix", `sk_xxxx_1234567890abcdefgHIJKLMN`, false},
	{"standard - uppercase prefix", `SK_LIVE_1234567890abcdefgHIJKLMN`, false},
	{"standard - missing separator", `sk_live1234567890abcdefgHIJKLMN`, false},
	{"standard - wrong separator", `sk_live-1234567890abcdefgHIJKLMN`, false},
	{"standard - missing suffix", `sk_live`, false},
	{"standard - illegal character suffix", `sk_live_123456789-abcdefgHIJKLMN`, false},
	{"standard - suffix too long", `sk_live_1234567890abcdefgHIJKLMNO`, false},
	{"standard - suffix too short", `sk_live_1234567890abcdefgHIJKLM`, false},

	{"restricted - valid live", `rk_live_1234567890abcdefgHIJKLMN`, true},
	{"restricted - valid test", `rk_test_1234567890abcdefgHIJKLMN`, true},
	{"restricted - partial prefix", `rk_1234567890abcdefgHIJKLMN`, false},
	{"restricted - illegal prefix", `rk_xxxx_1234567890abcdefgHIJKLMN`, false},
	{"restricted - uppercase prefix", `RK_LIVE_1234567890abcdefgHIJKLMN`, false},
	{"restricted - missing separator", `rk_live1234567890abcdefgHIJKLMN`, false},
	{"restricted - wrong separator", `rk_live-1234567890abcdefgHIJKLMN`, false},
	{"restricted - missing suffix", `rk_live`, false},
	{"restricted - illegal character suffix", `rk_live_123456789-abcdefgHIJKLMN`, false},
	{"restricted - suffix too long", `rk_live_1234567890abcdefgHIJKLMNO`, false},
	{"restricted - suffix too short", `rk_live_1234567890abcdefgHIJKLM`, false},

	{"empty input", "", false},
}

var stripeDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, stripeDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, stripeDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, stripeDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, stripeDetector, testCases)
}
