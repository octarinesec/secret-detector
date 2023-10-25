package bearerauth

import (
	"encoding/base64"
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
	"strings"
)

const (
	Name       = "bearer_auth"
	secretType = "HTTP Bearer Authentication"

	// bearerAuthRegex represents a regex that matches HTTP bearer authentication.
	bearerAuthRegex = `(?i)(?:\"?authorization\"? *[:=] *)?\"?bearer(?-i) +[a-zA-Z0-9+\/,_\-.=]{2,}\"?`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

type detector struct {
	secrets.Detector
}

func NewDetector(config ...string) secrets.Detector {
	return &detector{
		Detector: helpers.NewRegexDetectorBuilder(secretType, bearerAuthRegex).WithVerifier(isParameterValidBase64).WithKeyValueRegexWithoutNewLine().Build(),
	}
}

func isParameterValidBase64(_, s string) bool {
	words := strings.Split(s, " ")
	if len(words) == 0 {
		return false
	}
	parameter := words[len(words)-1]
	if parameter[len(parameter)-1] == '"' { // clean the optional " at the end
		parameter = parameter[:len(parameter)-1]
	}

	_, err := base64.StdEncoding.DecodeString(parameter)
	return err == nil
}
