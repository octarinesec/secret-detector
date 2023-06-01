package github

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"ghp prefix", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},
	{"gho prefix", "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},
	{"ghu prefix", "ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},
	{"ghs prefix", "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},
	{"ghr prefix", "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},

	{"missing prefix", "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", false},
	{"illegal prefix", "ghx_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", false},
	{"uppercase prefix", "GHP_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", false},

	{"missing separator", "ghpaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", false},
	{"illegal separator", "ghp-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", false},

	{"missing suffix", "ghp", false},
	{"illegal characters suffix", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789=", false},
	{"suffix too long", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678901", false},
	{"suffix too short", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789", false},

	{"empty input", "", false},
}

var githubDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, githubDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, githubDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, githubDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, githubDetector, testCases)
}
