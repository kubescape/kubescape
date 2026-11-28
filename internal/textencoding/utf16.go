// Package textencoding normalizes the encoding of user-supplied input files.
package textencoding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"golang.org/x/text/encoding/unicode"
)

// ErrInvalidUTF16 is returned for input that starts with a UTF-16 byte order mark
// but isn't valid UTF-16.
var ErrInvalidUTF16 = errors.New("invalid UTF-16 text")

var (
	utf16LEBOM = []byte{0xFF, 0xFE}
	utf16BEBOM = []byte{0xFE, 0xFF}
)

// DecodeUTF16 returns data as UTF-8, without the byte order mark, when it starts
// with a UTF-16 one. Windows PowerShell 5.1 writes redirected output that way, so
// "kubectl get pods -o yaml > pods.yaml" produces such a file. Any other input is
// returned unchanged.
//
// Text with half a code unit or an unpaired surrogate is rejected. The x/text
// decoder would put U+FFFD in its place, silently changing a name or a value.
func DecodeUTF16(data []byte) ([]byte, error) {
	var order binary.ByteOrder
	switch {
	case bytes.HasPrefix(data, utf16LEBOM):
		order = binary.LittleEndian
	case bytes.HasPrefix(data, utf16BEBOM):
		order = binary.BigEndian
	default:
		return data, nil
	}
	if !wellFormed(data, order) {
		return nil, ErrInvalidUTF16
	}
	// ExpectBOM takes the byte order from the mark and drops it.
	return unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM).NewDecoder().Bytes(data)
}

// wellFormed reports whether data is whole 16-bit units in which every surrogate
// is part of a high and low pair.
func wellFormed(data []byte, order binary.ByteOrder) bool {
	if len(data)%2 != 0 {
		return false
	}
	for i := 0; i < len(data); i += 2 {
		r := rune(order.Uint16(data[i:]))
		if !utf16.IsSurrogate(r) {
			continue
		}
		if i+4 > len(data) || utf16.DecodeRune(r, rune(order.Uint16(data[i+2:]))) == '\uFFFD' {
			return false
		}
		i += 2
	}
	return true
}
