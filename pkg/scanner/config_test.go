package scanner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfigFromJson(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  Config
		expectErr bool
	}{
		{
			"omitted fields preserve defaults",
			`{}`,
			NewConfigWithDefaults(),
			false,
		}, {
			"empty fields override defaults",
			`{"transformers": null, "detectors": null, "threshold_in_bytes": 0}`,
			NewConfigBuilder().Build(),
			false,
		}, {
			"config is loaded correctly",
			`{"transformers": ["a", "b", "c"], "detectors": ["d", "e", "f"], "threshold_in_bytes": 42}`,
			NewConfigBuilder().
				AppendTransformers("a", "b", "c").
				AppendDetectors("d", "e", "f").
				SetThreshold(42).Build(),
			false,
		}, {
			"illegal format returns error",
			`{`,
			Config{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewConfigFromJson(strings.NewReader(test.input))
			assert.Equal(t, test.expected, actual)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewConfigFromYaml(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  Config
		expectErr bool
	}{
		{
			"omitted fields preserve defaults",
			``,
			NewConfigWithDefaults(),
			false,
		}, {
			"empty fields override defaults",
			"transformers: null\ndetectors: null\nthreshold_in_bytes: 0",
			NewConfigBuilder().Build(),
			false,
		}, {
			"config is loaded correctly",
			"transformers:\n - a\n - b\n - c\n" +
				"detectors:\n - d\n - e\n - f\n" +
				"threshold_in_bytes: 42",
			NewConfigBuilder().
				AppendTransformers("a", "b", "c").
				AppendDetectors("d", "e", "f").
				SetThreshold(42).Build(),
			false,
		}, {
			"illegal format returns error",
			"\ttransformers: null\n\tdetectors: null\n\tthreshold_in_bytes: 0",
			Config{},
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewConfigFromYaml(strings.NewReader(test.input))
			assert.Equal(t, test.expected, actual)
			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
