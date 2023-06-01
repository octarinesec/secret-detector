package tests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

type TestCase struct {
	Name, Input     string
	ExpectDetection bool
}

func TestScan(t *testing.T, detector secrets.Detector, testCases []TestCase) {
	t.Helper()

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			detectedSecrets, err := detector.Scan(test.Input)

			assert.NoError(t, err)
			if test.ExpectDetection {
				if assert.Len(t, detectedSecrets, 1) {
					assert.Equal(t, detector.SecretType(), detectedSecrets[0].Type)
					assert.NotEmpty(t, detectedSecrets[0].Value)
				}
			} else {
				assert.Len(t, detectedSecrets, 0)
			}
		})
	}
}

func TestScanWithKey(t *testing.T, detector secrets.Detector, testCases []TestCase) {
	t.Helper()

	for i, test := range testCases {
		t.Run(test.Name+" (with key)", func(t *testing.T) {
			key := fmt.Sprintf("key%v", i)
			input := fmt.Sprintf("%v=%v", key, test.Input)
			detectedSecrets, err := detector.Scan(input)

			assert.NoError(t, err)
			if test.ExpectDetection {
				if assert.Len(t, detectedSecrets, 1) {
					assert.Equal(t, key, detectedSecrets[0].Key)
					assert.Equal(t, detector.SecretType(), detectedSecrets[0].Type)
					assert.NotEmpty(t, detectedSecrets[0].Value)
				}
			} else {
				assert.Len(t, detectedSecrets, 0)
			}
		})
	}
}

func TestScanWithMultipleMatches(t *testing.T, detector secrets.Detector, testCases []TestCase) {
	t.Helper()
	TestScanWithMultipleMatchesWithoutKey(t, detector, testCases)
	TestScanWithMultipleMatchesWithKey(t, detector, testCases)
}

func TestScanWithMultipleMatchesWithoutKey(t *testing.T, detector secrets.Detector, testCases []TestCase) {
	t.Helper()

	t.Run("Test Scan with multiple matches", func(t *testing.T) {
		var input string
		expectedDetections := 0
		for _, test := range testCases {
			input += test.Input + "\n"
			if test.ExpectDetection {
				expectedDetections++
			}
		}

		detectedSecrets, err := detector.Scan(input)

		assert.NoError(t, err)
		assert.Len(t, detectedSecrets, expectedDetections)
	})
}

func TestScanWithMultipleMatchesWithKey(t *testing.T, detector secrets.Detector, testCases []TestCase) {
	t.Helper()

	t.Run("Test Scan with multiple matches (with keys)", func(t *testing.T) {
		var input string
		expectedKeys := make([]string, 0)
		for i, test := range testCases {
			expectedKey := fmt.Sprintf("key%v", i)
			input += fmt.Sprintf("%v: %v\n", expectedKey, test.Input)
			if test.ExpectDetection {
				expectedKeys = append(expectedKeys, expectedKey)
			}
		}

		detectedSecrets, err := detector.Scan(input)

		assert.NoError(t, err)
		AssertKeysDetected(t, expectedKeys, detector.SecretType(), detectedSecrets)
	})
}

func TestScanMap(t *testing.T, detector secrets.Detector, testCases []TestCase) {
	t.Helper()

	t.Run("Test ScanMap", func(t *testing.T) {
		input := make(map[string]string, len(testCases))
		expectedKeys := make([]string, 0)
		for i, test := range testCases {
			expectedKey := fmt.Sprintf("key%v", i)
			input[expectedKey] = test.Input
			if test.ExpectDetection {
				expectedKeys = append(expectedKeys, expectedKey)
			}
		}

		detectedSecrets, err := detector.ScanMap(input)

		assert.NoError(t, err)
		AssertKeysDetected(t, expectedKeys, detector.SecretType(), detectedSecrets)
	})

	t.Run("Test ScanMap with no detections", func(t *testing.T) {
		input := map[string]string{
			"key1": "this is not a secret",
			"key2": "nothing interesting here",
		}
		detectedSecrets, err := detector.ScanMap(input)

		assert.NoError(t, err)
		assert.Len(t, detectedSecrets, 0)
	})
}

func AssertKeysDetected(t *testing.T, expectedKeys []string, expectedType string, detectedSecrets []secrets.DetectedSecret) {
	t.Helper()

	if !assert.Len(t, detectedSecrets, len(expectedKeys)) {
		return
	}

	detectedSecretsMap := make(map[string]secrets.DetectedSecret, len(detectedSecrets))
	for _, secret := range detectedSecrets {
		detectedSecretsMap[secret.Key] = secret
	}

	for _, expectedKey := range expectedKeys {
		secret, found := detectedSecretsMap[expectedKey]
		if assert.True(t, found) {
			assert.Equal(t, expectedKey, secret.Key)
			assert.Equal(t, expectedType, secret.Type)
			assert.NotEmpty(t, secret.Value)
		}
	}
}
