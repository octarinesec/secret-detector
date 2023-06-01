package npm

import (
	"testing"

	"github.com/octarinesec/secret-detector/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"auth token - default domain", `//registry.npmjs.org/:_authToken=0af23f36-c523-4c87-b543-18ff3ed79bce`, true},
	{"auth token - ip", `//192.168.1.1/:_authToken=Hardcoded_Npm_Token`, true},
	{"auth token - ip & port", `//127.0.0.1:8281/:_authToken=832aa750-1f92-450c-916a-e81e61740991`, true},

	{"auth token - missing leading slash", `/registry.npmjs.org/:_authToken=b1cc9fe0-9c1b-42fe-afaf-f06c0bbb65e2`, false},
	{"auth token - missing prefix", `_authToken=a5714101-fdcf-4b46-9202-00070aa84b52`, false},
	{"auth token - missing token key", `//registry.npmjs.org/1e58e90b-28c5-465c-911a-15e58211ca23`, false},
	{"auth token - missing token value", `//registry.npmjs.org/:_authToken=`, false},
	{"auth token - token value is a $ variable", `//registry.npmjs.org/:_authToken=$NPM_TOKEN`, false},
	{"auth token - token value is a {} expression", `//registry.npmjs.org/:_authToken={NPM_TOKEN}`, false},

	{"access token - valid", `npm_abcdefghijklmNOPQRSTUVWXYZ1234567890`, true},

	{"access token - missing prefix", `abcdefghijklmNOPQRSTUVWXYZ1234567890`, false},
	{"access token - wrong prefix", `npc_abcdefghijklmNOPQRSTUVWXYZ1234567890`, false},
	{"access token - uppercase prefix", `NPM_abcdefghijklmNOPQRSTUVWXYZ1234567890`, false},
	{"access token - missing separator", `npmabcdefghijklmNOPQRSTUVWXYZ1234567890`, false},
	{"access token - wrong separator", `npm-abcdefghijklmNOPQRSTUVWXYZ1234567890`, false},
	{"access token - missing body", `npm_`, false},
	{"access token - body too short", `npm_abcdefghijklmNOPQRSTUVWXYZ123456789`, false},
	{"access token - body too long", `npm_abcdefghijklmNOPQRSTUVWXYZ1234567890a`, false},
	{"access token - illegal characters in body", `npm_abcdefghijklmNOPQRSTUVWXY_1234567890`, false},

	{"empty input", "", false},
}

var npmTokenDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, npmTokenDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, npmTokenDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, npmTokenDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, npmTokenDetector, testCases)
}
