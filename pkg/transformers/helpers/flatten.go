package helpers

import "fmt"

func Flatten(in interface{}) map[string]string {
	out := make(map[string]string)
	flattenRecursive("", in, out)
	return out
}

// modified from https://stackoverflow.com/a/64420075/133665
func flattenRecursive(prefix string, in interface{}, out map[string]string) {
	switch obj := in.(type) {
	case map[string]interface{}:
		if len(prefix) > 0 {
			prefix += "."
		}
		for k, v := range obj {
			flattenRecursive(prefix+k, v, out)
		}
	case []interface{}:
		for elemIndex, elem := range obj {
			flattenRecursive(fmt.Sprintf("%v[%v]", prefix, elemIndex), elem, out)
		}
	default:
		out[prefix] = fmt.Sprint(obj)
	}
}
