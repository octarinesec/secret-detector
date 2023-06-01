package mailchimp

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name        = "mailchimp"
	secretType  = "Mailchimp API Key"
	apiKeyRegex = `[0-9a-f]{32}-us[0-9]{1,2}`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector() secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, apiKeyRegex),
	}
}
