package cel

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/kubernetes/scheme"
)

// normalizeNullFields returns obj with each null replaced by what the
// apiserver's typed decoding leaves in its place, so a policy offline sees the
// object admission would.
//
// A manifest key with nothing after it (`env:`, `annotations:`, an empty Helm
// block) is null in the file. The apiserver decodes a built-in kind into its Go
// struct before any policy runs, and what a null becomes there depends on the
// field's type: an omitempty pointer, slice, map or scalar is simply unset, so
// the key is gone; a field tagged omitzero is dropped too, since a null always
// decodes to its zero value; a struct is its zero value; and an entry of a map
// or list keeps its key or index with the element's zero value (`data: {k:
// null}` is `{k: ""}` for a map of strings). Left raw, the null makes has()
// true and the next list or map step errors, which a Fail policy reports as a
// violation admission would never make.
//
// Only kinds the client-go scheme knows are touched. A custom resource is left
// exactly as written, because its schema may declare a field nullable, and then
// the apiserver keeps the null too. Fields the Go type does not declare are left
// as written as well, and so is the value of a type that decodes its own JSON
// (Quantity, IntOrString, Time) unless it is null.
//
// The input is never mutated. An object with no nulls is returned as is, and
// only the maps and lists on the way to a null are copied.
func normalizeNullFields(obj map[string]any) map[string]any {
	if !containsNull(obj) {
		return obj
	}
	t, ok := builtinType(obj)
	if !ok {
		return obj
	}
	out, _ := normalizeNulls(obj, t)
	m, _ := out.(map[string]any)
	return m
}

// normalizeNulls rewrites the nulls under v, a value decoded into type t, and
// reports whether it changed anything.
func normalizeNulls(v any, t reflect.Type) (any, bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if decodesItsOwnJSON(t) {
		return v, false
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return v, false
		}
		fields := jsonFieldsOf(t)
		var out map[string]any
		for k, val := range m {
			f, known := fields[k]
			if !known {
				continue
			}
			if val == nil {
				switch f.nullDecoding() {
				case nullUnset:
					out = cloneOnce(out, m)
					delete(out, k)
				case nullZero:
					out = cloneOnce(out, m)
					out[k] = zeroValueOf(f.typ)
				}
				continue
			}
			if n, changed := normalizeNulls(val, f.typ); changed {
				out = cloneOnce(out, m)
				out[k] = n
			}
		}
		if out == nil {
			return v, false
		}
		return out, true
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return v, false
		}
		var out map[string]any
		for k, val := range m {
			if n, changed := normalizeElement(val, t.Elem()); changed {
				out = cloneOnce(out, m)
				out[k] = n
			}
		}
		if out == nil {
			return v, false
		}
		return out, true
	case reflect.Slice:
		l, ok := v.([]any)
		if !ok {
			return v, false
		}
		var out []any
		for i, val := range l {
			if n, changed := normalizeElement(val, t.Elem()); changed {
				if out == nil {
					out = slices.Clone(l)
				}
				out[i] = n
			}
		}
		if out == nil {
			return v, false
		}
		return out, true
	}
	return v, false
}

// normalizeElement handles one entry of a map or list. A null entry keeps its
// key or index: it decodes to the element type's zero value, which is still a
// null for a pointer, slice or map element.
func normalizeElement(val any, elem reflect.Type) (any, bool) {
	if val != nil {
		return normalizeNulls(val, elem)
	}
	if nullable(elem.Kind()) {
		return nil, false
	}
	return zeroValueOf(elem), true
}

type nullOutcome int

const (
	nullKept  nullOutcome = iota // the decoded field still serializes as null
	nullUnset                    // the field is omitted, so the key is gone
	nullZero                     // the field holds its type's zero value
)

type jsonField struct {
	typ       reflect.Type
	omitempty bool
	omitzero  bool
}

// nullDecoding says what a null in this field becomes after decoding into the
// Go struct and converting back: JSON leaves the field at its zero value,
// omitzero drops any zero value (a null always decodes to one, structs such as
// metav1.Time included), and omitempty drops a zero pointer, slice, map or
// scalar but never a struct.
func (f jsonField) nullDecoding() nullOutcome {
	if f.omitzero {
		return nullUnset
	}
	kind := f.typ.Kind()
	switch {
	case kind == reflect.Struct:
		return nullZero
	case f.omitempty:
		return nullUnset
	case nullable(kind):
		return nullKept
	}
	return nullZero
}

func nullable(kind reflect.Kind) bool {
	switch kind {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface:
		return true
	}
	return false
}

func cloneOnce(out, m map[string]any) map[string]any {
	if out == nil {
		return maps.Clone(m)
	}
	return out
}

func containsNull(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case map[string]any:
		for _, val := range x {
			if containsNull(val) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if containsNull(val) {
				return true
			}
		}
	}
	return false
}

var jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()

// decodesItsOwnJSON reports whether t has its own UnmarshalJSON. Its non-null
// values are left as written, since only the type knows what it accepts.
func decodesItsOwnJSON(t reflect.Type) bool {
	return reflect.PointerTo(t).Implements(jsonUnmarshaler)
}

var builtinTypes sync.Map // schema.GroupVersionKind -> reflect.Type, or nil when unknown

// builtinType returns the Go struct the apiserver decodes obj into, for a kind
// the client-go scheme registers.
func builtinType(obj map[string]any) (reflect.Type, bool) {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil || kind == "" {
		return nil, false
	}
	gvk := gv.WithKind(kind)
	if cached, ok := builtinTypes.Load(gvk); ok {
		t, _ := cached.(reflect.Type)
		return t, t != nil
	}
	var t reflect.Type
	if typed, err := scheme.Scheme.New(gvk); err == nil {
		t = reflect.TypeOf(typed)
	}
	builtinTypes.Store(gvk, t)
	return t, t != nil
}

var fieldsByType sync.Map // reflect.Type -> map[string]jsonField

// jsonFieldsOf maps the JSON names of t's fields to their types, flattening
// embedded structs the way encoding/json does (TypeMeta under a kind).
func jsonFieldsOf(t reflect.Type) map[string]jsonField {
	if cached, ok := fieldsByType.Load(t); ok {
		return cached.(map[string]jsonField)
	}
	fields := map[string]jsonField{}
	var direct []reflect.StructField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if f.Tag.Get("json") == "-" {
			continue
		}
		embedded := f.Type
		if embedded.Kind() == reflect.Pointer {
			embedded = embedded.Elem()
		}
		if f.Anonymous && name == "" && embedded.Kind() == reflect.Struct {
			for k, v := range jsonFieldsOf(embedded) {
				if _, taken := fields[k]; !taken {
					fields[k] = v
				}
			}
			continue
		}
		if f.IsExported() {
			direct = append(direct, f)
		}
	}
	for _, f := range direct {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" {
			name = f.Name
		}
		field := jsonField{typ: f.Type}
		for _, opt := range strings.Split(opts, ",") {
			switch opt {
			case "omitempty":
				field.omitempty = true
			case "omitzero":
				field.omitzero = true
			}
		}
		fields[name] = field
	}
	fieldsByType.Store(t, fields)
	return fields
}

var zeroValues sync.Map // reflect.Type -> any

// zeroValueOf is what a JSON null decoded into t serializes back to: t's zero
// value, or whatever its own UnmarshalJSON makes of null. Each call returns a
// fresh copy, since the result goes into an object a policy reads.
func zeroValueOf(t reflect.Type) any {
	cached, ok := zeroValues.Load(t)
	if !ok {
		cached = encodeZero(t)
		zeroValues.Store(t, cached)
	}
	if cached == nil {
		return nil
	}
	return runtime.DeepCopyJSONValue(cached)
}

func encodeZero(t reflect.Type) any {
	z := reflect.New(t)
	if err := json.Unmarshal([]byte("null"), z.Interface()); err != nil {
		return nil
	}
	b, err := json.Marshal(z.Interface())
	if err != nil {
		return nil
	}
	var out any
	if err := utiljson.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}
