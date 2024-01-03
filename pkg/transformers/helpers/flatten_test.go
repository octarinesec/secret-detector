package helpers

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	j = `{
			"pure_value": 123, 
			"array_of_objects": [ { "id": 1 }, {"id": 2, "another_value": true }],
			"subobject": { "subarray": [1, 2, 3], "second_level_object":  { "string": "str", "number": 123.1 } },
			"null": null
		}`
)

func TestFlattenRecursive(t *testing.T) {
	var jsonMap map[string]any
	err := json.Unmarshal([]byte(j), &jsonMap)

	assert.NoError(t, err)

	flattened := Flatten(jsonMap)

	assert.Contains(t, flattened, "pure_value")
	assert.Equal(t, "123", flattened["pure_value"])
	assert.Contains(t, flattened, "null")
	assert.Equal(t, "", flattened["null"])
	assert.Contains(t, flattened, "array_of_objects[0].id")
	assert.Equal(t, "1", flattened["array_of_objects[0].id"])
	assert.Contains(t, flattened, "array_of_objects[1].another_value")
	assert.Equal(t, "true", flattened["array_of_objects[1].another_value"])
	assert.Contains(t, flattened, "subobject.subarray[2]")
	assert.Equal(t, "3", flattened["subobject.subarray[2]"])
	assert.Contains(t, flattened, "subobject.second_level_object.string")
	assert.Equal(t, "str", flattened["subobject.second_level_object.string"])
	assert.Contains(t, flattened, "subobject.second_level_object.number")
	assert.Equal(t, "123.1", flattened["subobject.second_level_object.number"])
}
