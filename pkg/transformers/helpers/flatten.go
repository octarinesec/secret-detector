package helpers

import (
	"fmt"
	"strconv"
)

func Flatten(in interface{}) map[string]string {
	out := make(map[string]string)
	initial := make([]byte, 0, 64)
	flattenRecursive(&initial, in, out)
	return out
}

// flattenRecursive flattens a JSON object into a map where each parent array or object for a field is appended to the its new key
// For example { "a" : { "b" : "c" } } should become { "a.b" : "c" }
// it is assumed that the root call is made with a JSON object and not a raw value or array
//
// prefixAcc keeps the prefix so far in a slice buffer
func flattenRecursive(prefixAcc *[]byte, in any, out map[string]string) {
	// Note: if prefixAcc is []byte instead of *[]byte, then the slice header is copied on each call
	// there is a chance that the byte array might be moved due to a required resize
	// and then the caller's slice will no longer point to the same array, hence keeping both in memory for some time
	// Which is why we use a pointer in the recursion and all calls should opearate on the same slice header
	prefix := *prefixAcc

	if in == nil {
		out[string(prefix)] = ""
		return
	}

	switch obj := in.(type) {
	case map[string]any:
		if len(prefix) > 0 {
			prefix = append(prefix, '.')
		}
		for k, v := range obj {
			prefix = append(prefix, []byte(k)...)
			flattenRecursive(&prefix, v, out)
			prefix = prefix[:len(prefix)-len(k)]
		}
		if len(prefix) > 0 { // Remove the "." that we added
			prefix = prefix[:len(prefix)-1]
		}
	case []any:
		prefix = append(prefix, '[')
		for elemIndex := range obj {
			s := strconv.Itoa(elemIndex)
			prefix = append(prefix, []byte(s)...)
			prefix = append(prefix, ']')
			flattenRecursive(&prefix, obj[elemIndex], out)
			prefix = prefix[:len(prefix)-len(s)-1] // Remove "index]"
		}
		prefix = prefix[:len(prefix)-1] // Remove the '['
	case string:
		out[string(prefix)] = obj
	case int:
		out[string(prefix)] = strconv.Itoa(obj)
	case int64:
		out[string(prefix)] = strconv.FormatInt(obj, 10)
	case uint64:
		out[string(prefix)] = strconv.FormatUint(obj, 10)
	case bool:
		out[string(prefix)] = strconv.FormatBool(obj)
	default:
		out[string(prefix)] = fmt.Sprint(obj)
	}
}

func flattenRecursive2(prefix string, in interface{}, out map[string]string) {
	switch obj := in.(type) {
	case map[string]interface{}:
		if len(prefix) > 0 {
			prefix += "."
		}
		for k, v := range obj {
			flattenRecursive2(prefix+k, v, out)
		}
	case []interface{}:
		for elemIndex, elem := range obj {
			flattenRecursive2(fmt.Sprintf("%v[%v]", prefix, elemIndex), elem, out)
		}
	default:
		out[prefix] = fmt.Sprint(obj)
	}
}
