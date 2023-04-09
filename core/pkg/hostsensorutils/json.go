package hostsensorutils

import (
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
