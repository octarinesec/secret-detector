package basicauth

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
)

const (
	Name       = "basic_auth"
	secretType = "HTTP Basic Authentication"

	// basicAuthRegex represents a regex that matches HTTP basic authentication.
	basicAuthRegex = `(?i)(?:\"?authorization\"? *[:=] *)?\"?basic(?-i) +[a-zA-Z0-9+/,_\-]{2,}={0,2}\"?`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector() secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, basicAuthRegex),
	}
}
