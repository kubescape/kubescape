package cel

import (
	"maps"
	"slices"
)

// withoutNullFields returns obj with every null-valued map key dropped, at any
// depth.
//
// A manifest key with nothing after it (`env:`, `annotations:`, an empty Helm
// block) decodes to null. The apiserver never shows that null to a policy: it
// decodes the object into its typed struct first, where a null field is simply
// unset, so has() is false and the field reads as absent. Left in place, the
// null makes has() true and the list or map step after it errors, which a Fail
// policy turns into a violation admission would never report.
//
// Only map values are dropped. A null list element is left alone so list
// indices, and the paths built from them, stay the same as in the manifest.
//
// The input is never mutated. An object with no nulls is returned as is, and
// only the maps and lists on the way to a null are copied.
func withoutNullFields(obj map[string]any) map[string]any {
	pruned, _ := pruneNulls(obj)
	m, _ := pruned.(map[string]any)
	return m
}

// pruneNulls reports whether v held a null map value; when it did, the returned
// value is a copy with those keys dropped.
func pruneNulls(v any) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		var out map[string]any
		for k, val := range x {
			if val == nil {
				if out == nil {
					out = maps.Clone(x)
				}
				delete(out, k)
				continue
			}
			if pruned, changed := pruneNulls(val); changed {
				if out == nil {
					out = maps.Clone(x)
				}
				out[k] = pruned
			}
		}
		if out == nil {
			return x, false
		}
		return out, true
	case []any:
		var out []any
		for i, val := range x {
			if pruned, changed := pruneNulls(val); changed {
				if out == nil {
					out = slices.Clone(x)
				}
				out[i] = pruned
			}
		}
		if out == nil {
			return x, false
		}
		return out, true
	}
	return v, false
}
