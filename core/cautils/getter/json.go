package getter

import (
	"strings"

	stdjson "encoding/json"

	jsoniter "github.com/json-iterator/go"
)

var (
	json jsoniter.API
)

func init() {
	// NOTE(fredbi): attention, this configuration rounds floats down to 6 digits
	// For finer-grained config, see: https://pkg.go.dev/github.com/json-iterator/go#section-readme
	json = jsoniter.ConfigFastest
}

// JSONDecoder returns JSON decoder for given string
func JSONDecoder(origin string) *stdjson.Decoder {
	dec := stdjson.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()
	return dec
}
