package aws

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
)

const (
	MWSKeyDetectorName       = "aws_mws_key"
	mwsKeyDetectorSecretType = "Amazon Marketplace Web Service (MWS) Key"
	// mwsKeyRegex represents a regex that matches Amazon Marketplace Web Service key.
	mwsKeyRegex = `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
)

func init() {
	secrets.GetDetectorFactory().Register(MWSKeyDetectorName, NewMWSKeyDetector)
}

type mwsKeyDetector struct {
	secrets.Detector
}

func NewMWSKeyDetector(config ...string) secrets.Detector {
	return &mwsKeyDetector{
		Detector: helpers.NewRegexDetector(mwsKeyDetectorSecretType, mwsKeyRegex),
	}
}
