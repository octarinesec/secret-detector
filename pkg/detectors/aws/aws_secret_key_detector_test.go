package aws

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
	"testing"
)

var secretKeyTestCases = []tests.TestCase{

	{"valid key - lowercase prefix", `aws"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, true},
	{"valid key - uppercase prefix", `AWS"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, true},
	{"valid key - extended prefix", `aws="12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, true},
	{"valid key - max length extended prefix", `aws1234567890abcdefghij"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, true},
	{"valid key - single quoted suffix", `aws'12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+'`, true},

	{"missing prefix", `"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, false},
	{"illegal prefix", `xxx"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, false},
	{"too long prefix", `aws1234567890abcdefghijk"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+"`, false},

	{"missing suffix", `aws`, false},
	{"illegal characters suffix", `aws"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ="`, false},
	{"missing quotes", `aws12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+`, false},
	{"suffix too long", `aws"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ+1"`, false},
	{"suffix too short", `aws"12345+67890/abcdefghijklm+NOPQRSTUVWXYZ"`, false},
	{"empty input", "", false},
}

var secretKeyDetector = NewSecretKeyDetector()

func TestSecretKeyDetector_Scan(t *testing.T) {
	tests.TestScan(t, secretKeyDetector, secretKeyTestCases)
}

func TestSecretKeyDetector_ScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, secretKeyDetector, secretKeyTestCases)
}

func TestSecretKeyDetector_ScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, secretKeyDetector, secretKeyTestCases)
}

func TestSecretKeyDetector_ScanMap(t *testing.T) {
	tests.TestScanMap(t, secretKeyDetector, secretKeyTestCases)
}
