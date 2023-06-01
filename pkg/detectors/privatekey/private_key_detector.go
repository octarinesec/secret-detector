package privatekey

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name       = "pk"
	secretType = "Private Key"
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

var privateKeysRegex = []string{
	".*BEGIN DSA PRIVATE KEY.*",
	".*BEGIN EC PRIVATE KEY.*",
	".*BEGIN OPENSSH PRIVATE KEY.*",
	".*BEGIN PGP PRIVATE KEY BLOCK.*",
	".*BEGIN PRIVATE KEY.*",
	".*BEGIN RSA PRIVATE KEY.*",
	".*BEGIN SSH2 ENCRYPTED PRIVATE KEY.*",
	".*PuTTY-User-Key-File-.*",
}

type detector struct {
	secrets.Detector
}

func NewDetector() secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, privateKeysRegex...),
	}
}
