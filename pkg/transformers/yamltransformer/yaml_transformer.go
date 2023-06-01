package yamltransformer

import (
	"gitlab.bit9.local/octarine/detect-secrets/pkg/dataformat"
	"gopkg.in/yaml.v3"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/transformers/helpers"
)

const (
	Name = "yaml"
)

var supportedFormats = []dataformat.DataFormat{dataformat.YAML}

func init() {
	secrets.GetTransformerFactory().Register(Name, NewTransformer)
}

type transformer struct {
}

func NewTransformer() secrets.Transformer {
	return &transformer{}
}

func (t *transformer) Transform(in string) (map[string]string, bool) {
	yamlMap := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(in), &yamlMap); err != nil {
		return nil, false
	}
	return helpers.Flatten(yamlMap), true
}

func (t *transformer) SupportedFormats() []dataformat.DataFormat {
	return supportedFormats
}

func (t *transformer) SupportFiles() bool {
	return true
}
