// Package textencoding normalizes the encoding of user-supplied input files.
package textencoding

import (
	"bytes"

	"golang.org/x/text/encoding/unicode"
)

var (
	utf16LEBOM = []byte{0xFF, 0xFE}
	utf16BEBOM = []byte{0xFE, 0xFF}
)

// DecodeUTF16 returns data as UTF-8, without the byte order mark, when it starts
// with a UTF-16 one. Windows PowerShell 5.1 writes redirected output that way, so
// "kubectl get pods -o yaml > pods.yaml" produces such a file. Any other input is
// returned unchanged, as is input that cannot be decoded, so that the caller's
// parser reports it.
func DecodeUTF16(data []byte) []byte {
	if !bytes.HasPrefix(data, utf16LEBOM) && !bytes.HasPrefix(data, utf16BEBOM) {
		return data
	}
	// ExpectBOM takes the byte order from the mark and drops it.
	decoded, err := unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM).NewDecoder().Bytes(data)
	if err != nil {
		return data
	}
	return decoded
}
