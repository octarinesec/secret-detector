package privatekey

import (
	"testing"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/tests"
)

var testCases = []tests.TestCase{
	{"DSA PRIVATE KEY", "-----BEGIN DSA PRIVATE KEY-----\nwxyz+ABC=\n-----END DSA PRIVATE KEY-----", true},
	{"EC PRIVATE KEY", "-----BEGIN EC PRIVATE KEY-----\nwxyz+ABC=\n-----END EC PRIVATE KEY-----", true},
	{"OPENSSH PRIVATE KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\nwxyz+ABC=\n-----END OPENSSH PRIVATE KEY-----", true},
	{"PGP PRIVATE KEY BLOCK", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nwxyz+ABC=\n-----END PGP PRIVATE KEY BLOCK-----", true},
	{"PRIVATE KEY", "-----BEGIN PRIVATE KEY-----\nwxyz+ABC=\n-----END PRIVATE KEY-----", true},
	{"RSA PRIVATE KEY", "-----BEGIN RSA PRIVATE KEY-----\nwxyz+ABC=\n-----END RSA PRIVATE KEY-----", true},
	{"SSH2 ENCRYPTED PRIVATE KEY", "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----\nwxyz+ABC=\n-----END SSH2 ENCRYPTED PRIVATE KEY-----", true},
	{"SSH2 ENCRYPTED PRIVATE KEY", "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----\nwxyz+ABC=\n-----END SSH2 ENCRYPTED PRIVATE KEY-----", true},
	{"PuTTY 2", "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nPublic lines: 1\nwxyz+ABC==\nPrivate-Lines: 1\nwxyz+ABC=\nPrivate-MAC: 00000006760c0a30106e329351 a0051ac87aoffe\n", true},
	{"PuTTY 3", "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nPublic lines: 1\nwxyz+ABC==\nPrivate-Lines: 1\nwxyz+ABC=\nPrivate-MAC: 00000006760c0a30106e329351 a0051ac87aoffe\n", true},
	{"Not a private key", "THIS IS NOT A PRIVATE KEY", false},
	{"empty input", "", false},
}

var pkDetector = NewDetector()

func TestScan(t *testing.T) {
	tests.TestScan(t, pkDetector, testCases)
}

func TestScanWithKey(t *testing.T) {
	tests.TestScanWithKey(t, pkDetector, testCases)
}

func TestScanWithMultipleMatches(t *testing.T) {
	tests.TestScanWithMultipleMatches(t, pkDetector, testCases)
}

func TestScanMap(t *testing.T) {
	tests.TestScanMap(t, pkDetector, testCases)
}
