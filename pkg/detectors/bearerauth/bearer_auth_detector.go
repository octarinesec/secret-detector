package bearerauth

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
)

const (
	Name       = "bearer_auth"
	secretType = "HTTP Bearer Authentication"

	// bearerAuthRegex represents a regex that matches HTTP bearer authentication.
	bearerAuthRegex = `(?i)(?:\"?authorization\"? *[:=] *)?\"?bearer(?-i) +[a-zA-Z0-9+/,_\-.=]{2,}\"?`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector(config ...string) secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetector(secretType, bearerAuthRegex),
	}
}
