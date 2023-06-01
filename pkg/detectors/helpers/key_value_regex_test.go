package helpers

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	lowercaseKeyRegex    = `key_\d+`
	lowercaseValueRegex  = `value_\d+`
	uppercaseValueRegex  = `VALUE_\d+`
	submatchesValueRegex = `(value)(_)(\d+)`
)

var (
	defaultKVRegex    = NewDefaultKeyValueRegex(lowercaseValueRegex)
	kvMultipleRegex   = NewDefaultKeyValueRegex(lowercaseValueRegex, uppercaseValueRegex)
	kvSubmatchesRegex = NewDefaultKeyValueRegex(submatchesValueRegex)
	kvRegex           = NewKeyValueRegex(lowercaseKeyRegex, lowercaseValueRegex)
)

type testCase struct {
	name, input                                                      string
	isExpected                                                       bool
	expectedFullMatch, expectedKey, expectedDelimiter, expectedValue string
}

var testCases = []testCase{
	{name: `value only`, input: "value_101", isExpected: true, expectedFullMatch: "value_101", expectedValue: "value_101"},
	{name: `value only - no match`, input: "VALUE_101", isExpected: false},
	{name: `value surrounded by whitespace`, input: "  	value_102	 ", isExpected: true, expectedFullMatch: "value_102", expectedValue: "value_102"},
	{name: `value surrounded by whitespace - no match`, input: "  	VALUE_102	 ", isExpected: false},
	{name: `"value"`, input: ` "value_103"	`, isExpected: true, expectedFullMatch: `"value_103"`, expectedValue: "value_103"},
	{name: `"value" - no match`, input: ` "VALUE_103"	`, isExpected: false},
	{name: `'value'`, input: `'value_104'`, isExpected: true, expectedFullMatch: `'value_104'`, expectedValue: "value_104"},
	{name: `'value' - no match`, input: `'VALUE_104'`, isExpected: false},
	{name: `[value]`, input: `[value_105]`, isExpected: true, expectedFullMatch: `[value_105]`, expectedValue: "value_105"},
	{name: `[value] - no match`, input: `[VALUE_105]`, isExpected: false},
	{name: `head_value`, input: `head_value_106`, isExpected: false},
	{name: `value_tail`, input: `value_107_tail`, isExpected: false},
	{name: `value space tail`, input: `value_108 tail`, isExpected: true, expectedFullMatch: "value_108", expectedValue: "value_108"},
	{name: `[ value ]`, input: `[ value_109 ]`, isExpected: true, expectedFullMatch: `[ value_109 ]`, expectedValue: "value_109"},
	{name: `[ value ] - no match`, input: `[ VALUE_109 ]`, isExpected: false},
	{name: `key value (key without delimiter not caught)`, input: `key_201 value_201`, isExpected: true, expectedFullMatch: `value_201`, expectedValue: "value_201"},
	{name: `key=value`, input: `key_202=value_202`, isExpected: true, expectedFullMatch: `key_202=value_202`, expectedKey: "key_202", expectedDelimiter: "=", expectedValue: "value_202"},
	{name: `key=value - no match`, input: `key_202=VALUE_202`, isExpected: false},
	{name: `key: value`, input: `key_203: value_203`, isExpected: true, expectedFullMatch: `key_203: value_203`, expectedKey: "key_203", expectedDelimiter: ":", expectedValue: "value_203"},
	{name: `key: value - no match`, input: `key_203: VALUE_203`, isExpected: false},
	{name: `key := value`, input: `key_204 := value_204`, isExpected: true, expectedFullMatch: `key_204 := value_204`, expectedKey: "key_204", expectedDelimiter: ":=", expectedValue: "value_204"},
	{name: `'key'=value`, input: `'key_205'=value_205`, isExpected: true, expectedFullMatch: `'key_205'=value_205`, expectedKey: "key_205", expectedDelimiter: "=", expectedValue: "value_205"},
	{name: `'key'=value - no match`, input: `'key_205'=VALUE_205`, isExpected: false},
	{name: `"key"="value"`, input: `"key_206"="value_206"`, isExpected: true, expectedFullMatch: `"key_206"="value_206"`, expectedKey: "key_206", expectedDelimiter: "=", expectedValue: "value_206"},
	{name: `"key"="value" - no match`, input: `"key_206"="VALUE_206"`, isExpected: false},
	{name: `"key" = 'value'`, input: `"key_207" = 'value_207'`, isExpected: true, expectedFullMatch: `"key_207" = 'value_207'`, expectedKey: "key_207", expectedDelimiter: "=", expectedValue: "value_207"},
	{name: `"key" = 'value' - no match`, input: `"key_207" = 'VALUE_207'`, isExpected: false},
	{name: `key = value`, input: `key_208 = value_208`, isExpected: true, expectedFullMatch: `key_208 = value_208`, expectedKey: "key_208", expectedDelimiter: "=", expectedValue: "value_208"},
	{name: `key = value - no match`, input: `key_208 = VALUE_208`, isExpected: false},
	{name: `key with space = value`, input: `key 209 = value_209`, isExpected: true, expectedFullMatch: `key 209 = value_209`, expectedKey: "key 209", expectedDelimiter: "=", expectedValue: "value_209"},
	{name: `key with space = value - no match`, input: `key 209 = VALUE_209`, isExpected: false},
	{name: `key/with/slash=value`, input: `key/210=value_210`, isExpected: true, expectedFullMatch: `key/210=value_210`, expectedKey: "key/210", expectedDelimiter: "=", expectedValue: "value_210"},
	{name: `key/with/slash=value`, input: `key/209=VALUE_209`, isExpected: false},
	{name: `  key	with	tab=value  `, input: `  key		211=value_211  `, isExpected: true, expectedFullMatch: `key		211=value_211`, expectedKey: `key		211`, expectedDelimiter: "=", expectedValue: "value_211"},
	{name: `  key	with	tab=value  - no match`, input: `  key		211=VALUE_211  `, isExpected: false},
	{name: `[key = value]`, input: `[key_212 = value_212]`, isExpected: true, expectedFullMatch: `[key_212 = value_212]`, expectedKey: "key_212", expectedDelimiter: "=", expectedValue: "value_212"},
	{name: `[key = value] - no match`, input: `[key_212 = VALUE_212]`, isExpected: false},
	{name: `key=value;`, input: `key_213=value_213;`, isExpected: true, expectedFullMatch: `key_213=value_213;`, expectedKey: "key_213", expectedDelimiter: "=", expectedValue: "value_213"},
	{name: `key=head_value`, input: `key_214=head_value_214`, isExpected: false},
	{name: `key=value_tail`, input: `key_215=value_215_tail`, isExpected: false},
	{name: `key=value space tail`, input: `key_216=value_216 tail`, isExpected: true, expectedFullMatch: `key_216=value_216`, expectedKey: "key_216", expectedDelimiter: "=", expectedValue: "value_216"},
	{name: `$key = value`, input: `$key_217 = value_217`, isExpected: true, expectedFullMatch: `$key_217 = value_217`, expectedKey: "$key_217", expectedDelimiter: "=", expectedValue: "value_217"},
	{name: `$key = value - no match`, input: `$key_217 = VALUE_217`, isExpected: false},
	{name: `export KEY=value`, input: `export KEY_218=value_218`, isExpected: true, expectedFullMatch: `export KEY_218=value_218`, expectedKey: "KEY_218", expectedDelimiter: "=", expectedValue: "value_218"},
	{name: `export KEY=value - no match`, input: `export KEY_218=VALUE_218`, isExpected: false},
	{name: `SET key=value`, input: `SET key_219=value_219`, isExpected: true, expectedFullMatch: `SET key_219=value_219`, expectedKey: "key_219", expectedDelimiter: "=", expectedValue: "value_219"},
	{name: `SET key=value - no match`, input: `SET key_219=VALUE_219`, isExpected: false},
	{name: `"key" = "value";`, input: `"key_220" = "value_220";`, isExpected: true, expectedFullMatch: `"key_220" = "value_220";`, expectedKey: "key_220", expectedDelimiter: "=", expectedValue: "value_220"},
	{name: `"key" = "value"; - no match`, input: `"key_220" = "VALUE_220";`, isExpected: false},
	{name: `[ "key" ] = [ "value" ]`, input: `[ "key_221" ] = [ "value_221" ]`, isExpected: true, expectedFullMatch: `[ "key_221" ] = [ "value_221" ]`, expectedKey: "key_221", expectedDelimiter: "=", expectedValue: "value_221"},
	{name: `[ "key" ] = [ "value" ] - no match`, input: `[ "key_221" ] = [ "VALUE_221" ]`, isExpected: false},
	{name: `[ key ]=[ value ]`, input: `[ key_222 ]=[ value_222 ]`, isExpected: true, expectedFullMatch: `[ key_222 ]=[ value_222 ]`, expectedKey: "key_222", expectedDelimiter: "=", expectedValue: "value_222"},
	{name: `[ key ]=[ value ] - no match`, input: `[ key_222 ]=[ VALUE_222 ]`, isExpected: false},
	{name: `[ "key" ] = [ "value" ] ;`, input: `[ "key_223" ] = [ "value_223" ] 	;`, isExpected: true, expectedFullMatch: `[ "key_223" ] = [ "value_223" ] 	;`, expectedKey: "key_223", expectedDelimiter: "=", expectedValue: "value_223"},
	{name: `[ "key" ] = [ "value" ] ; - no match`, input: `[ "key_223" ] = [ "VALUE_223" ] 	;`, isExpected: false},
	{name: `empty input`, input: ``, isExpected: false},
}

var testCasesMultipleRegex = []testCase{
	{name: `value only`, input: "value_101", isExpected: true, expectedFullMatch: "value_101", expectedValue: "value_101"},
	{name: `VALUE only`, input: "VALUE_102", isExpected: true, expectedFullMatch: "VALUE_102", expectedValue: "VALUE_102"},
	{name: `key=value`, input: `key_103=value_103`, isExpected: true, expectedFullMatch: `key_103=value_103`, expectedKey: "key_103", expectedDelimiter: "=", expectedValue: "value_103"},
	{name: `key=VALUE`, input: `key_104=VALUE_104`, isExpected: true, expectedFullMatch: `key_104=VALUE_104`, expectedKey: "key_104", expectedDelimiter: "=", expectedValue: "VALUE_104"},
	{name: `key=value - no match`, input: `key_105=105`, isExpected: false},
	{name: `empty input`, input: ``, isExpected: false},
}

var testCasesKeyValue = []testCase{
	{name: `key = value`, input: ` key_101 = value_101 `, isExpected: true, expectedFullMatch: "key_101 = value_101", expectedKey: "key_101", expectedDelimiter: "=", expectedValue: "value_101"},
	{name: `"key": "value"`, input: `"key_102": "value_102"`, isExpected: true, expectedFullMatch: `"key_102": "value_102"`, expectedKey: "key_102", expectedDelimiter: ":", expectedValue: "value_102"},
	{name: `'key' := 'value'`, input: `	'key_103' := 'value_103'	`, isExpected: true, expectedFullMatch: `'key_103' := 'value_103'`, expectedKey: "key_103", expectedDelimiter: ":=", expectedValue: "value_103"},
	{name: `only key matched`, input: `key_201=201`, isExpected: false},
	{name: `only value matched`, input: `k_202=value_202`, isExpected: false},
	{name: `both not matched`, input: `k_203=v_203`, isExpected: false},
	{name: `key only`, input: `key_204`, isExpected: false},
	{name: `value only`, input: `value_205`, isExpected: false},
	{name: `empty input`, input: ``, isExpected: false},
}

func TestFindAll(t *testing.T) {
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			actualMatches, err := defaultKVRegex.FindAll(test.input)
			assert.NoError(t, err)
			if test.isExpected {
				if assert.Len(t, actualMatches, 1) {
					assertMatch(t, test, actualMatches[0])
				}
			} else {
				assert.Len(t, actualMatches, 0)
			}
		})
	}
}

func TestFindAll_MultipleMatches(t *testing.T) {
	t.Run("Test FindAll with multiple matches", func(t *testing.T) {
		var input string
		expectedMatches := make([]testCase, 0)
		for _, test := range testCases {
			input += fmt.Sprintf("%v\n", test.input)
			if test.isExpected {
				expectedMatches = append(expectedMatches, test)
			}
		}

		actualMatches, err := defaultKVRegex.FindAll(input)
		assert.NoError(t, err)
		assertMatches(t, expectedMatches, actualMatches)
	})
}

func TestFindAll_MultipleRegex(t *testing.T) {
	for _, test := range testCasesMultipleRegex {
		t.Run(test.name, func(t *testing.T) {
			actualMatches, err := kvMultipleRegex.FindAll(test.input)
			assert.NoError(t, err)
			if test.isExpected {
				if assert.Len(t, actualMatches, 1) {
					assertMatch(t, test, actualMatches[0])
				}
			} else {
				assert.Len(t, actualMatches, 0)
			}
		})
	}
}

func TestFindAll_MultipleRegexMultipleMatches(t *testing.T) {
	t.Run("Test FindAll with multiple matches", func(t *testing.T) {
		var input string
		expectedMatches := make([]testCase, 0)
		for _, test := range testCasesMultipleRegex {
			input += fmt.Sprintf("%v\n", test.input)
			if test.isExpected {
				expectedMatches = append(expectedMatches, test)
			}
		}

		actualMatches, err := kvMultipleRegex.FindAll(input)
		assert.NoError(t, err)
		assertMatches(t, expectedMatches, actualMatches)
	})
}

func TestFindAll_Submatches(t *testing.T) {
	t.Run("Test FindAll with value submatches", func(t *testing.T) {
		test := testCase{
			input:             `key_101 = value_101`,
			isExpected:        true,
			expectedFullMatch: `key_101 = value_101`,
			expectedKey:       "key_101",
			expectedDelimiter: "=",
			expectedValue:     "value_101",
		}
		expectedValueSubmatches := []string{"value", "_", "101"}

		actualMatches, err := kvSubmatchesRegex.FindAll(test.input)
		assert.NoError(t, err)
		if assert.Len(t, actualMatches, 1) {
			assertMatch(t, test, actualMatches[0])
			assert.Equal(t, expectedValueSubmatches, actualMatches[0].ValueSubmatches)
		}
	})
}

func TestFindAll_KeyValue(t *testing.T) {
	for _, test := range testCasesKeyValue {
		t.Run(test.name, func(t *testing.T) {
			actualMatches, err := kvRegex.FindAll(test.input)
			assert.NoError(t, err)
			if test.isExpected {
				if assert.Len(t, actualMatches, 1) {
					assertMatch(t, test, actualMatches[0])
				}
			} else {
				assert.Len(t, actualMatches, 0)
			}
		})
	}
}

func TestFindAll_KeyValueMultipleMatches(t *testing.T) {
	t.Run("Test FindAll with multiple matches", func(t *testing.T) {
		var input string
		expectedMatches := make([]testCase, 0)
		for _, test := range testCasesKeyValue {
			input += fmt.Sprintf("%v\n", test.input)
			if test.isExpected {
				expectedMatches = append(expectedMatches, test)
			}
		}

		actualMatches, err := kvRegex.FindAll(input)
		assert.NoError(t, err)
		assertMatches(t, expectedMatches, actualMatches)
	})
}

func assertMatch(t *testing.T, expected testCase, actual MatchResult) {
	t.Helper()

	assert.Equal(t, expected.expectedFullMatch, actual.FullMatch)
	assert.Equal(t, expected.expectedKey, actual.Key)
	assert.Equal(t, expected.expectedDelimiter, actual.Delimiter)
	assert.Equal(t, expected.expectedValue, actual.Value)
}

func assertMatches(t *testing.T, expectedMatches []testCase, actualMatches []MatchResult) {
	t.Helper()

	if !assert.Len(t, actualMatches, len(expectedMatches)) {
		return
	}

	expectedMatchesMap := make(map[string]testCase, len(expectedMatches))
	for _, expected := range expectedMatches {
		expectedMatchesMap[expected.expectedValue] = expected
	}

	for _, actual := range actualMatches {
		expected, found := expectedMatchesMap[actual.Value]
		if assert.True(t, found) {
			assertMatch(t, expected, actual)
		}
	}
}
