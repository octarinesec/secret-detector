package generic

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var urlPwdTestCases = []tests.TestCase{
	{"url with pwd", "https://user:p455w0rd@example.com", true},
	{"shortest url with pwd", "aa://u:p@d", true},
	{"long url with pwd", "bitcoin://very-very-very-very-very-very-very-very-very-long-user:very-very-very-very-very-very-very-very-very-long-pass@very-very-very-very-very-very-very-very-very-long-subdomain.very-very-very-very-very-very-very-very-very-long-domain.com:8082/very-very-very-very-very-very-very-very-very-long-path.html?param1=value1&param2=value2#fragment", true},
	{"url with email user", "smtp://user@example.com:p455w0rd@smtp.example.com:465/", true},

	{"missing scheme", "user:p455w0rd@example.com", false},
	{"missing domain", "https://user:p455w0rd@", false},
	{"empty user", "https://:p455w0rd@example.com", false},
	{"empty pwd", "https://user:@example.com", false},
	{"missing pwd", "https://user@example.com", false},
	{"missing user & pwd", "https://example.com", false},
	{"variable pwd", "https://user:$pwd@example.com", false},
	{"illegal url characters", "https://user:{pwd}@example.com", false},

	{"empty input", "", false},
}

var urlPwdDetector = NewURLPasswordDetector()

func TestURLPasswordDetector_Scan(t *testing.T) {
	tests.TestScan(t, urlPwdDetector, urlPwdTestCases)
}

func TestURLPasswordDetector_ScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, urlPwdDetector, urlPwdTestCases)
}

func TestURLPasswordDetector_ScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, urlPwdDetector, urlPwdTestCases)
}

func TestURLPasswordDetector_ScanMap(t *testing.T) {
	tests.TestScanMap(t, urlPwdDetector, urlPwdTestCases)
}
