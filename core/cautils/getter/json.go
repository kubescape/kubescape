package getter

import (
	"bytes"

	jsoniter "github.com/json-iterator/go"
)

var json jsoniter.API

func init() {
	// NOTE(fredbi): attention, this configuration rounds floats down to 6 digits
	// For finer-grained config, see: https://pkg.go.dev/github.com/json-iterator/go#section-readme
	json = jsoniter.ConfigFastest
}

// utf8BOM is the byte order mark that Windows editors, and Windows PowerShell's
// Out-File -Encoding utf8, write at the start of a file.
var utf8BOM = []byte("\xef\xbb\xbf")

// decodePolicyJSON decodes the contents of a local policy file (a framework,
// control, exceptions, controls inputs or attack tracks file) into v. A leading
// UTF-8 byte order mark is not part of the JSON text, and the decoder would
// reject the whole file at its first byte, so it is skipped. Only the decoded
// view changes: callers keep the bytes as read, so digests of the consumed file
// still match the file on disk.
func decodePolicyJSON(buf []byte, v any) error {
	return json.Unmarshal(bytes.TrimPrefix(buf, utf8BOM), v)
}
