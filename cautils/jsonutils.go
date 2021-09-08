package cautils

import (
	"bytes"
	"encoding/json"
)

const (
	empty = ""
	tab   = "  "
)

func PrettyJson(data interface{}) ([]byte, error) {
	buffer := new(bytes.Buffer)
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent(empty, tab)

	err := encoder.Encode(data)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
