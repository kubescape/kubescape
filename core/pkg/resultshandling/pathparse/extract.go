package pathparse

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
)

// NormalizeForPathExtraction converts obj into a tree built entirely from
// encoding/json's generic decoding types (map[string]any, []any, json.Number,
// string, bool, nil). Earlier processing stages (such as workload.GetContainers())
// can leave typed Go structs in place of plain maps/slices; round-tripping
// through JSON once per resource makes the whole tree walkable uniformly.
//
// Numbers are decoded as json.Number rather than float64 so large integers
// keep their literal digits when rendered.
func NormalizeForPathExtraction(obj map[string]any) map[string]any {
	b, err := json.Marshal(obj)
	if err != nil {
		return obj
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var normalized map[string]any
	if err := dec.Decode(&normalized); err != nil {
		return obj
	}
	return normalized
}

// ResolveSegments walks obj along segments and returns the value found there.
func ResolveSegments(obj map[string]any, segments []Segment) (any, bool) {
	var cur any = obj
	for _, seg := range segments {
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[seg.Key]
			if !ok {
				return nil, false
			}
			if seg.Index >= 0 {
				elem, ok := IndexList(next, seg.Index)
				if !ok {
					return nil, false
				}
				cur = elem
			} else {
				cur = next
			}
		default:
			if seg.Key != "" {
				return nil, false
			}
			elem, ok := IndexList(v, seg.Index)
			if !ok {
				return nil, false
			}
			cur = elem
		}
	}
	return cur, true
}

// IndexList returns the element at index i of a slice.
func IndexList(v any, i int) (any, bool) {
	if i < 0 {
		return nil, false
	}
	switch arr := v.(type) {
	case []any:
		if i >= len(arr) {
			return nil, false
		}
		return arr[i], true
	case []map[string]any:
		if i >= len(arr) {
			return nil, false
		}
		return arr[i], true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice || i >= rv.Len() {
		return nil, false
	}
	return rv.Index(i).Interface(), true
}

// AnyToString converts a value to its string representation for evidence display.
func AnyToString(v any) (string, bool) {
	switch val := v.(type) {
	case nil:
		return "null", true
	case bool:
		return strconv.FormatBool(val), true
	case string:
		if val == "" {
			return `""`, true
		}
		return val, true
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10), true
		}
		return strconv.FormatFloat(val, 'f', -1, 64), true
	case int:
		return strconv.Itoa(val), true
	case int32:
		return strconv.FormatInt(int64(val), 10), true
	case int64:
		return strconv.FormatInt(val, 10), true
	case uint:
		return strconv.FormatUint(uint64(val), 10), true
	case uint32:
		return strconv.FormatUint(uint64(val), 10), true
	case uint64:
		return strconv.FormatUint(val, 10), true
	case json.Number:
		return val.String(), true
	case map[string]any, []any:
		b, err := json.Marshal(val)
		if err != nil {
			return "", false
		}
		return string(b), true
	default:
		return "", false
	}
}

// ExtractRawValue resolves path against obj and formats the resulting value as
// text without redaction or masking. Callers must ensure obj has been
// normalized via NormalizeForPathExtraction when typed Go structs may be present.
func ExtractRawValue(obj map[string]any, path string) (string, bool) {
	val, _, ok := ExtractRawValueResolved(obj, path)
	return val, ok
}

// ExtractRawValueResolved resolves path against obj and returns its formatted text representation,
// whether the resolved value in the resource object was a structured object/list (map or slice)
// rather than a scalar, and whether the path resolved successfully.
func ExtractRawValueResolved(obj map[string]any, path string) (string, bool, bool) {
	if len(obj) == 0 || path == "" {
		return "", false, false
	}
	segments, err := ParsePath(path)
	if err != nil || len(segments) == 0 {
		return "", false, false
	}
	cur, ok := ResolveSegments(obj, segments)
	if !ok {
		return "", false, false
	}
	isStructured := false
	switch cur.(type) {
	case map[string]any, []any, []map[string]any:
		isStructured = true
	default:
		rv := reflect.ValueOf(cur)
		if rv.IsValid() && (rv.Kind() == reflect.Map || rv.Kind() == reflect.Slice) {
			isStructured = true
		}
	}
	str, ok := AnyToString(cur)
	return str, isStructured, ok
}
