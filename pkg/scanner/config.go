package scanner

import (
	"encoding/json"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/transformers/command"
	"io"

	"gopkg.in/yaml.v3"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/artifactory"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/aws"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/azure"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/basicauth"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/bearerauth"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/generic"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/github"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/jwt"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/keyword"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/mailchimp"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/npm"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/privatekey"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/sendgrid"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/slack"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/square"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/stripe"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/twilio"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/transformers/initransformer"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/transformers/jsontransformer"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/transformers/xmltransformer"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/transformers/yamltransformer"
)

const (
	DefaultThreshold int = 10 * 1e6 // 10MB
)

// Config represents a scanner configuration.
// Omitted fields will preserve the values of the default configuration.
//
// Notice: filesTransformers order may affect the results, because the algorithm breaks on first successful transform.
// So it's better to order them from most specific to the most general.
// e.g. json is usually a legal yaml, but not vice versa. Hence, json is more specific.
//
//	yaml is usually a valid ini, but usually not vice versa. Hence, yaml is more specific.
//
// Notice 2: detectors order may affect the results,
// because the algorithm breaks on first detection for single line input.
// So it's better to order them from most specific to the most general.
// e.g. GitHub key might also be a high entropy base64 string.
type Config struct {
	Transformers     []string `json:"transformers" yaml:"transformers"`
	Detectors        []string `json:"detectors" yaml:"detectors"`
	ThresholdInBytes int      `json:"threshold_in_bytes" yaml:"threshold_in_bytes"`
}

func NewConfigWithDefaults() Config {
	return Config{
		Transformers: []string{
			jsontransformer.Name,
			yamltransformer.Name,
			xmltransformer.Name,
			initransformer.Name,
			command.Name,
		},
		Detectors: []string{
			artifactory.Name,
			aws.ClientIdDetectorName,
			aws.SecretKeyDetectorName,
			aws.MWSKeyDetectorName,
			azure.Name,
			basicauth.Name,
			bearerauth.Name,
			github.Name,
			jwt.Name,
			keyword.Name,
			mailchimp.Name,
			npm.Name,
			privatekey.Name,
			sendgrid.Name,
			slack.Name,
			square.Name,
			stripe.Name,
			twilio.Name,
			generic.URLPasswordDetectorName,
			generic.HighEntropyStringDetectorName,
		},
		ThresholdInBytes: DefaultThreshold,
	}
}

func NewConfigFromJson(r io.Reader) (Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Config{}, err
	}

	c := NewConfigWithDefaults()
	err = json.Unmarshal(b, &c)
	if err != nil {
		return Config{}, err
	}

	return c, err
}

func NewConfigFromYaml(r io.Reader) (Config, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Config{}, err
	}

	c := NewConfigWithDefaults()
	err = yaml.Unmarshal(b, &c)
	if err != nil {
		return Config{}, err
	}

	return c, err
}

type ConfigBuilder struct {
	config Config
}

func NewConfigBuilder() ConfigBuilder {
	return ConfigBuilder{}
}

func NewConfigBuilderFrom(config Config) ConfigBuilder {
	return ConfigBuilder{config}
}

func (builder ConfigBuilder) AppendTransformers(transformers ...string) ConfigBuilder {
	builder.config.Transformers = append(builder.config.Transformers, transformers...)
	return builder
}

func (builder ConfigBuilder) RemoveTransformers(transformers ...string) ConfigBuilder {
	for _, transformer := range transformers {
		builder.config.Transformers = removeFrom(builder.config.Transformers, transformer)
	}
	return builder
}

func (builder ConfigBuilder) AppendDetectors(detectors ...string) ConfigBuilder {
	builder.config.Detectors = append(builder.config.Detectors, detectors...)
	return builder
}

func (builder ConfigBuilder) RemoveDetectors(detectors ...string) ConfigBuilder {
	for _, detector := range detectors {
		builder.config.Detectors = removeFrom(builder.config.Detectors, detector)
	}
	return builder
}

func (builder ConfigBuilder) SetThreshold(thresholdInBytes int) ConfigBuilder {
	builder.config.ThresholdInBytes = thresholdInBytes
	return builder
}

func (builder ConfigBuilder) Build() Config {
	return builder.config
}

func removeFrom(slice []string, element string) []string {
	for i, s := range slice {
		if s == element {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
