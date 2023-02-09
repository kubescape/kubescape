package getter

import (
	"io"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

var json jsoniter.API

func init() {
	// NOTE(fredbi): attention, this configuration rounds floats down to 6 digits
	// For finer-grained config, see: https://pkg.go.dev/github.com/json-iterator/go#section-readme
	json = jsoniter.ConfigFastest
}

// JSONDecoder provides a low-level utility that returns a JSON decoder for given string.
//
// Deprecated: use higher level methods from the KSCloudAPI client instead.
func JSONDecoder(origin string) *jsoniter.Decoder {
	dec := jsoniter.NewDecoder(strings.NewReader(origin))
	dec.UseNumber()

	return dec
}

func decode[T any](rdr io.Reader) (T, error) {
	var receiver T
	dec := newDecoder(rdr)
	err := dec.Decode(&receiver)

	return receiver, err
}

func newDecoder(rdr io.Reader) *jsoniter.Decoder {
	return json.NewDecoder(rdr)
}
