package textencoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeUTF16(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
		want []byte
	}{
		{name: "little endian", in: []byte{0xFF, 0xFE, 'a', 0, 0xE9, 0}, want: []byte("aé")},
		{name: "big endian", in: []byte{0xFE, 0xFF, 0, 'a', 0, 0xE9}, want: []byte("aé")},
		{name: "surrogate pair", in: []byte{0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE}, want: []byte("\U0001F600")},
		{name: "byte order mark only", in: []byte{0xFF, 0xFE}, want: []byte{}},
		{name: "plain UTF-8", in: []byte("kind: Pod"), want: []byte("kind: Pod")},
		{name: "UTF-8 with a byte order mark is left alone", in: []byte("\xef\xbb\xbfa"), want: []byte("\xef\xbb\xbfa")},
		{name: "UTF-16 without a byte order mark is left alone", in: []byte{'a', 0}, want: []byte{'a', 0}},
		{name: "empty", in: nil, want: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeUTF16(tt.in)
			require.NoError(t, err)
			assert.Equal(t, string(tt.want), string(got))
		})
	}
}

func TestDecodeUTF16Invalid(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []byte
	}{
		{name: "half a code unit", in: []byte{0xFF, 0xFE, 'a', 0, 'b'}},
		{name: "high surrogate at the end", in: []byte{0xFF, 0xFE, 0x00, 0xD8}},
		{name: "high surrogate before a letter", in: []byte{0xFF, 0xFE, 0x00, 0xD8, 'a', 0}},
		{name: "low surrogate alone", in: []byte{0xFF, 0xFE, 0x00, 0xDC}},
		{name: "big endian high surrogate alone", in: []byte{0xFE, 0xFF, 0xD8, 0x00}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeUTF16(tt.in)
			assert.ErrorIs(t, err, ErrInvalidUTF16)
		})
	}
}
