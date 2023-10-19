package generic

import (
	"github.com/octarinesec/secret-detector/pkg/detectors/helpers"
	"github.com/octarinesec/secret-detector/pkg/secrets"
	"net/url"
	"strings"
)

const (
	URLPasswordDetectorName       = "url_password"
	urlPasswordDetectorSecretType = "URL with password"

	// urlPasswordRegex represents a regex that matches urls with user & password.
	// e.g. scheme://user:pass@domain.com/
	urlPasswordRegex = `[a-z][a-z0-9+.-]+://[^:\s]+:[^@:\s]+@[^\s'"\];]+`
)

func init() {
	secrets.GetDetectorFactory().Register(URLPasswordDetectorName, NewURLPasswordDetector)
}

type urlPasswordDetector struct {
	secrets.Detector
}

func NewURLPasswordDetector(config ...string) secrets.Detector {
	return &urlPasswordDetector{
		Detector: helpers.NewRegexDetectorWithVerifier(isUrlWithPassword, urlPasswordDetectorSecretType, urlPasswordRegex),
	}
}

func isUrlWithPassword(_, s string) bool {
	u, _ := url.Parse(s)
	if u == nil || u.User == nil {
		return false
	}

	user := u.User.Username()
	pwd, _ := u.User.Password()
	return user != "" && pwd != "" && !strings.HasPrefix(pwd, "$")
}
