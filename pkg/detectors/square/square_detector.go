package square

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name             = "square"
	secretType       = "Square authentication"
	accessTokenRegex = `sq0atp-[0-9A-Za-z\\\-_]{22}`
	oAuthSecretRegex = `sq0csp-[0-9A-Za-z\\\-_]{43}`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

// detector for Square authentication - https://squareup.com/
type detector struct {
	secrets.Detector
}

func NewDetector() secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, accessTokenRegex, oAuthSecretRegex),
	}
}
