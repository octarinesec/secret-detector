package slack

import (
	"testing"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"bot token", `xoxb-1234-hJK89Qrst`, true},
	{"user token", `xoxp-1234-5678-xaK89e0`, true},
	{"app token", `xapp-1-QKDD2TWZ27V-0372407459206-989awefasdf98afaw8e9ruw98efuq9w8ef1nmqlr39098af98ankjnpq9a0kme09`, true},
	{"configuration access token", `xoxe.xoxp-1-Mi0yLTIzNDI1OTczMTE2OS0yMzc3NzQzMjAxMzc3LTMwNzUzNDk4NTA2ODktMzA2MjkyNjAxNjEzMC05NTM2MzcyYWJlMzU2NjEwZWExMmZhZjMyZmMyNWJhNDZmYjZkZmI3ZjgzYWFmOWFmYzM0M2IzNDAyYmUzYWI0`, true},
	{"configuration refresh token", `xoxe-1-My0xLTIzNDI1OTczMTE2OS0zMDc1MzQ5ODUwNjg5LTMwNjAwMTg1NTQ5MDEtOGFlNTY1N2JjOTg2ZWEyNWVlODNkYzJjN2EzNjlkZmY4M2RhYWFlOWY1ODkyOTFkNWJiNGEwNDY0YzQ4ODJjMg`, true},
	{"legacy workspace access token", `xoxa-2-JwQ879AaDAw9`, true},
	{"legacy workspace refresh token", `xoxr-2-JwQ879AaDAw9`, true},
	{"legacy xoxo token", `xoxo-100-pL4Sav7t`, true},
	{"legacy xoxs token", `xoxs-02-7Yq5eRv7c`, true},

	{"token missing prefix", `1234-hJK89Qrst`, false},
	{"token wrong prefix", `xoxx-1234-hJK89Qrst`, false},
	{"token uppercase prefix", `XOXB-1234-hJK89Qrst`, false},
	{"configuration access token with wrong prefix ", `xoxe.xoxs-1-lksef6Ao0w`, false},
	{"token missing body", `xoxb-`, false},
	{"token missing digits group", `xoxb-abcd-efgh`, false},
	{"token missing second group", `xoxb-1234`, false},
	{"token body contains illegal characters", `xoxp-1234-5678-xaK89e*`, false},

	{"webhook url - short", `https://hooks.slack.com/services/T0/B0/X`, true},
	{"webhook url - long", `https://hooks.slack.com/services/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`, true},

	{"webhook url with wrong schema", `http://hooks.slack.com/services/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`, false},
	{"webhook url with wrong domain", `https://hooks-slack.com/services/T3AQEJU4D/B9DBLTV2S/0mKbFowIBxhj6lPSos5ee3sk`, false},
	{"webhook url with missing T prefix", `https://hooks.slack.com/services/3AQEJU4D/B9DBLTV2S/0mKbFowIBxhj6lPSos5ee3sk`, false},
	{"webhook url with missing B prefix", `https://hooks.slack.com/services/T3AQEJU4D/9DBLTV2S/0mKbFowIBxhj6lPSos5ee3sk`, false},
	{"webhook url with missing last part", `https://hooks.slack.com/services/T3AQEJU4D/B9DBLTV2S/`, false},
	{"webhook url with illegal characters", `https://hooks.slack.com/services/T3AQEJU4D/B9DBLTV2S/0mKbFowIBxhj6lPSos5ee3s?`, false},

	{"empty input", "", false},
}

var slackDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, slackDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, slackDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, slackDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, slackDetector, testCases)
}
