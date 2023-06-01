package sendgrid

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"valid key #1", "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", true},
	{"valid key #2", "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", true},
	{"valid key #3", "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", true},

	{"missing prefix", "698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},
	{"illegal prefix", "SX.698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},
	{"lowercase prefix", "sg.698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},

	{"missing separator", "SG698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},
	{"illegal separator", "SG-698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},

	{"missing 2nd part", "SG.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},
	{"illegal characters 2nd part", "SG.698ZUNe1TdS3IoO20xMmN=.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},
	{"2nd part too long", "SG.698ZUNe1TdS3IoO20xMmNQq.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},
	{"2nd part too short", "SG.698ZUNe1TdS3IoO20xMmN.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-s", false},

	{"missing 3nd part", "SG.698ZUNe1TdS3IoO20xMmNQ", false},
	{"illegal characters 3nd part", "SG.698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1=LiD4HNe_Txx-s", false},
	{"3nd part too long", "SG.698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txx-sz", false},
	{"3nd part too short", "SG.698ZUNe1TdS3IoO20xMmNQ.ynhY7qoCJj_fHV2cd177nGkxGNhL1-LiD4HNe_Txxs", false},

	{"empty input", "", false},
}

var sendgridDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, sendgridDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, sendgridDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, sendgridDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, sendgridDetector, testCases)
}
