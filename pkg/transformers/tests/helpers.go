package tests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

type TestCase struct {
	Name, Input string
	Expected    map[string]string
}

func TestTransform(t *testing.T, transformer secrets.Transformer, testCases []TestCase) {
	t.Helper()

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			actual, ok := transformer.Transform(test.Input)

			assert.Equal(t, test.Expected != nil, ok)
			assert.Equal(t, test.Expected, actual)
		})
	}
}
