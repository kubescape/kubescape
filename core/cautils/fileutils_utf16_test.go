package cautils

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// utf16Text encodes text as UTF-16 with a byte order mark.
func utf16Text(order binary.AppendByteOrder, text string) []byte {
	var out []byte
	for _, unit := range utf16.Encode([]rune("\ufeff" + text)) {
		out = order.AppendUint16(out, unit)
	}
	return out
}

func TestReadFileUTF16(t *testing.T) {
	const twoPods = "apiVersion: v1\r\nkind: Pod\r\nmetadata:\r\n  name: first\r\n---\r\napiVersion: v1\r\nkind: Pod\r\nmetadata:\r\n  name: second\r\n"
	const jsonList = `[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"first"}},{"apiVersion":"v1","kind":"Pod","metadata":{"name":"second"}}]`

	for _, order := range []struct {
		name  string
		order binary.AppendByteOrder
	}{
		{name: "little endian", order: binary.LittleEndian},
		{name: "big endian", order: binary.BigEndian},
	} {
		for _, input := range []struct {
			name   string
			text   string
			format FileFormat
		}{
			{name: "multi-document YAML", text: twoPods, format: YAML_FILE_FORMAT},
			{name: "JSON", text: jsonList, format: JSON_FILE_FORMAT},
		} {
			t.Run(order.name+" "+input.name, func(t *testing.T) {
				workloads, err := ReadFile(utf16Text(order.order, input.text), input.format)
				require.NoError(t, err)

				var names []string
				for _, w := range workloads {
					names = append(names, w.GetName())
				}
				assert.Equal(t, []string{"first", "second"}, names)
			})
		}
	}
}
