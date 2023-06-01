package helpers

import (
	"github.com/octarinesec/secret-detector/pkg/secrets"
)

type DetectionVerifier func(string) bool

type regexDetector struct {
	secretType    string
	keyValueRegex *KeyValueRegex
	valueRegex    *ValueRegex
	verifier      DetectionVerifier
}

// NewRegexDetector creates a generic regex detector.
// It can be used as an embedded struct to implement most types of regex based detectors.
func NewRegexDetector(secretType string, regex ...string) secrets.Detector {
	return NewRegexDetectorWithVerifier(nil, secretType, regex...)
}

// NewRegexDetectorWithVerifier creates a generic regex detector.
// It can be used as an embedded struct to implement most types of regex based detectors.
// verifier function should check if the string matched by regex is a valid detection.
func NewRegexDetectorWithVerifier(verifier DetectionVerifier, secretType string, regex ...string) secrets.Detector {
	return &regexDetector{
		secretType:    secretType,
		keyValueRegex: NewDefaultKeyValueRegex(regex...),
		valueRegex:    NewValueRegex(regex...),
		verifier:      verifier,
	}
}

func (d *regexDetector) SecretType() string {
	return d.secretType
}

func (d *regexDetector) Scan(in string) ([]secrets.DetectedSecret, error) {
	res := make([]secrets.DetectedSecret, 0)
	matches, err := d.keyValueRegex.FindAll(in)
	for _, match := range matches {
		if d.verifyDetection(match.Value) {
			res = append(res, secrets.DetectedSecret{Key: match.Key, Type: d.SecretType(), Value: match.Value})
		}
	}
	return res, err
}

func (d *regexDetector) ScanMap(keyValueMap map[string]string) ([]secrets.DetectedSecret, error) {
	res := make([]secrets.DetectedSecret, 0)
	for key, value := range keyValueMap {
		if d.valueRegex.Match(value) && d.verifyDetection(value) {
			res = append(res, secrets.DetectedSecret{Key: key, Type: d.SecretType(), Value: value})
		}
	}
	return res, nil
}

func (d *regexDetector) verifyDetection(value string) bool {
	if d.verifier != nil {
		return d.verifier(value)
	}
	return true
}
