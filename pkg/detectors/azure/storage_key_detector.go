package azure

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
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

func NewDetector(config []string) secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, azureStorageKeyRegex),
	}
}
