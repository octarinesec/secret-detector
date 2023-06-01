package azure

import (
	"testing"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"valid key", `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuv==`, true},
	{"valid key - only letters", `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, true},
	{"valid key - only digits", `1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678`, true},
	{"too long", `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuvw==`, false},
	{"too short", `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstu==`, false},
	{"key with illegal characters", `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-/abcdefghijklmnopqrstuv==`, false},

	{"empty input", "", false},
}

var storageKeyDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, storageKeyDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, storageKeyDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, storageKeyDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, storageKeyDetector, testCases)
}
