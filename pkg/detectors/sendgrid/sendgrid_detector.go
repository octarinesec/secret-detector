package sendgrid

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name       = "sendgrid"
	secretType = "Sendgrid API key"

	// see https://docs.sendgrid.com/ui/account-and-settings/api-keys
	//     https://web.archive.org/web/20200202153737/https://d2w67tjf43xwdp.cloudfront.net/Classroom/Basics/API/what_is_my_api_key.html
	apiKeyRegex = `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`
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
