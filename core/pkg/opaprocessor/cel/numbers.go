package cel

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// jsonNumberAdapter preserves manifest numbers without treating json.Number as
// a string or rounding integers through float64. Other types use the base env.
type jsonNumberAdapter struct{ types.Adapter }

func (a jsonNumberAdapter) NativeToValue(value any) ref.Val {
	switch v := value.(type) {
	case json.Number:
		return jsonNumberValue(v)
	case map[string]any:
		return types.NewStringInterfaceMap(a, v)
	case []any:
		return types.NewDynamicList(a, v)
	default:
		return a.Adapter.NativeToValue(value)
	}
}

func jsonNumberValue(v json.Number) ref.Val {
	if i, err := v.Int64(); err == nil {
		return types.Int(i)
	}
	if u, err := strconv.ParseUint(string(v), 10, 64); err == nil {
		return types.Uint(u)
	}
	if !strings.ContainsAny(string(v), ".eE") {
		return types.NewErr("integer %q is out of range", v)
	}
	f, err := v.Float64()
	if err != nil {
		return types.NewErr("invalid JSON number %q: %v", v, err)
	}
	return types.Double(f)
}

// jsonNumberError finds unrepresentable number tokens in one raw binding.
func jsonNumberError(value any) *types.Err {
	switch v := value.(type) {
	case json.Number:
		err, _ := jsonNumberValue(v).(*types.Err)
		return err
	case map[string]any:
		for _, item := range v {
			if err := jsonNumberError(item); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := jsonNumberError(item); err != nil {
				return err
			}
		}
	}
	return nil
}
