package aws

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	SecretKeyDetectorName       = "aws_secret_key"
	secretKeyDetectorSecretType = "AWS Secret Key"
	awsSecretKeyRegex           = `(?:AWS|aws).{0,20}['\"][0-9a-zA-Z\/+]{40}['\"]`
)

func init() {
	secrets.GetDetectorFactory().Register(SecretKeyDetectorName, NewSecretKeyDetector)
}

type awsSecretKeyDetector struct {
	secrets.Detector
}

func NewSecretKeyDetector() secrets.Detector {
	return &awsSecretKeyDetector{
		Detector: helpers.NewRegexDetector(secretKeyDetectorSecretType, awsSecretKeyRegex),
	}
}
