package azure

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name                 = "azure"
	secretType           = "Azure Storage Account access key"
	azureStorageKeyRegex = `[a-zA-Z0-9+\/=]{88}`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector() secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, azureStorageKeyRegex),
	}
}
