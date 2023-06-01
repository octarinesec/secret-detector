package keyword

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"api_key", "api_key: 4P1_K3Y", true},
	{"apikey", "someAPIKey=50m34p1k3y", true},
	{"api-key", "api-key-prod=4p1-k3y-pr0d", true},
	{"private_key", "MY_APP_PRIVATE_KEY := my_4pp_pr1v473_k3y", true},
	{"password", "password: p455w0rd", true},
	{"pwd", `"myDatabasePwd" = "myd474b453pwd"`, true},
	{"secret", "'my_secret_code'='my_53cr37_c0d3'", true},
	{"account-key", `AWS-ACCOUNT-KEY: "4w5-4cc0un7-k3y"`, true},
	{"export token", "export NPM_TOKEN=npm_70k3n", true},
	{"keyword in value", "not_a_keyword = not_a_secret", false},
	{"value only", "secret_without_a_key", false},
	{"value is a variable", "password1: $MY_PASSWORD", false},
	{"value is an expression", "password2: {{ .secrets.password }}", false},
	{"empty input", "", false},
}

var keywordDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, keywordDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatchesWithoutKey(t, keywordDetector, testCases)
}

func TestScanMap(t *testing.T) {
	t.Run("Test ScanMap", func(t *testing.T) {
		input := make(map[string]string, len(testCases))
		expectedKeys := make([]string, 0)
		for _, test := range testCases {
			expectedKey, expectedValue := extractKeyValue(test.Input)
			input[expectedKey] = expectedValue
			if test.ExpectDetection {
				expectedKeys = append(expectedKeys, expectedKey)
			}
		}

		detectedSecrets, err := keywordDetector.ScanMap(input)

		assert.NoError(t, err)
		tests.AssertKeysDetected(t, expectedKeys, keywordDetector.SecretType(), detectedSecrets)
	})

	t.Run("Test ScanMap with no detections", func(t *testing.T) {
		input := make(map[string]string, len(testCases))
		for _, test := range testCases {
			if !test.ExpectDetection {
				k, v := extractKeyValue(test.Input)
				input[k] = v
			}
		}

		detectedSecrets, err := keywordDetector.ScanMap(input)

		assert.NoError(t, err)
		assert.Len(t, detectedSecrets, 0)
	})
}

func extractKeyValue(in string) (key, value string) {
	var parts []string
	for _, sep := range []string{":=", ":", "="} {
		parts = strings.SplitN(in, sep, 2)
		if len(parts) == 2 {
			break
		}
	}
	if len(parts) == 1 {
		value = parts[0]
	}
	if len(parts) == 2 {
		key = parts[0]
		value = parts[1]
	}
	return
}
