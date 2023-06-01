package github

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name       = "github"
	secretType = "Github authentication"

	// see https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	tokenRegex = `gh[pousr]_[A-Za-z0-9_]{36}`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector() secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, tokenRegex),
	}
}
