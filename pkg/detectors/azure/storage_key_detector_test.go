package azure

import (
	"testing"

	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"valid key", `AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuv==`, true},
	{"invalid key", `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuv==`, false},
	{"valid key - only letters", `AccountKey=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, true},
	{"invalid key - only letters", `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, false},
	{"valid key - only digits", `AccountKey=1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678`, true},
	{"invalid key - only digits", `1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678`, false},
	{"too long", `AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstuvw==`, false},
	{"too short", `AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/abcdefghijklmnopqrstu==`, false},
	{"key with illegal characters", `AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-/abcdefghijklmnopqrstuv==`, false},

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
