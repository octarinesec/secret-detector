package keyword

import (
	"fmt"
	"strings"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	Name = "keyword"

	// exclude values starting with $ because they are usually variables
	// exclude values surrounded by {} because they are usually computed expressions
	valuesRegex = `[^${\s].+[^}\s]`
)

func init() {
	secrets.GetDetectorFactory().Register(Name, NewDetector)
}

var suspiciousKeysRegex = []string{
	`api[-_]?key`,
	`access[-_]?key`,
	`auth[-_]?key`,
	`service[-_]?key`,
	`account[-_]?key`,
	`db[-_]?key`,
	`database[-_]?key`,
	`priv[-_]?key`,
	`private[-_]?key`,
	`client[-_]?key`,
	`db[-_]?pass`,
	`database[-_]?pass`,
	`key[-_]?pass`,
	`password`,
	`passwd`,
	`pwd`,
	`secret`,
	`token`,
	`contraseña`,
	`contrasena`,
}

// detector scans for secret-sounding variable names.
type detector struct {
	keyValueRegex *helpers.KeyValueRegex
	keyRegex      *helpers.ValueRegex
	valueRegex    *helpers.ValueRegex
}

func NewDetector() secrets.Detector {
	keyRegex := fmt.Sprintf(`[\.\[~\-\w]*(?i)(?:%s)(?-i)[\.\[\]~\-\w]*`, strings.Join(suspiciousKeysRegex, "|"))

	return &detector{
		keyValueRegex: helpers.NewKeyValueRegex(keyRegex, valuesRegex),
		keyRegex:      helpers.NewKeyRegex(keyRegex),
		valueRegex:    helpers.NewValueRegex(valuesRegex),
	}
}

func (_ *detector) SecretType() string {
	return "Keyword Detector"
}

func (d *detector) Scan(in string) ([]secrets.DetectedSecret, error) {
	res := make([]secrets.DetectedSecret, 0)
	matches, err := d.keyValueRegex.FindAll(in)
	for _, match := range matches {
		res = append(res, secrets.DetectedSecret{Key: match.Key, Type: d.SecretType(), Value: match.Value})
	}
	return res, err
}

func (d *detector) ScanMap(keyValueMap map[string]string) ([]secrets.DetectedSecret, error) {
	res := make([]secrets.DetectedSecret, 0)
	for key, value := range keyValueMap {
		if d.keyRegex.Match(key) && d.valueRegex.Match(value) {
			res = append(res, secrets.DetectedSecret{Key: key, Type: d.SecretType(), Value: value})
		}
	}
	return res, nil
}
