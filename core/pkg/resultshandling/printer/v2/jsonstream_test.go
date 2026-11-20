package printer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type shortWriter struct {
	max int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) <= w.max {
		return len(p), nil
	}
	return w.max, nil
}

type failingWriter struct {
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, w.err
}

func TestJSONStream_FramingAndFields(t *testing.T) {
	var buf bytes.Buffer
	s := newJSONStream(&buf)

	first := true
	s.raw("{")
	s.field(&first, "name", "kubescape")
	s.field(&first, "count", 3)
	s.field(&first, "enabled", true)
	s.raw("}")

	require.NoError(t, s.err)

	var parsed map[string]any
	err := json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err, "generated output must be valid JSON: %s", buf.String())

	assert.Equal(t, "kubescape", parsed["name"])
	assert.Equal(t, float64(3), parsed["count"])
	assert.Equal(t, true, parsed["enabled"])
}

func TestJSONStream_KeyEscaping(t *testing.T) {
	tests := []struct {
		name    string
		keyName string
	}{
		{name: "standard alphanumeric", keyName: "simpleKey"},
		{name: "resource id with slashes and colons", keyName: "apps/v1/namespaces/prod/deployments/web:8080"},
		{name: "quotes and backslashes", keyName: `key"with"quotes\and\slashes`},
		{name: "whitespace and controls", keyName: "key\nwith\tnewlines\r"},
		{name: "html brackets and unicode", keyName: "<script>alert('xss')</script> & 🔥"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			s := newJSONStream(&buf)

			first := true
			s.raw("{")
			s.field(&first, tt.keyName, "value")
			s.raw("}")

			require.NoError(t, s.err)

			var parsed map[string]string
			err := json.Unmarshal(buf.Bytes(), &parsed)
			require.NoError(t, err, "marshaled key must unmarshal back cleanly: %s", buf.String())
			assert.Equal(t, "value", parsed[tt.keyName])
		})
	}
}

func TestJSONStream_Separator(t *testing.T) {
	var buf bytes.Buffer
	s := newJSONStream(&buf)

	first := true
	s.separator(&first)
	assert.False(t, first)
	assert.Empty(t, buf.String(), "first separator should not write a comma")

	s.separator(&first)
	assert.Equal(t, ",", buf.String(), "subsequent separator should write a comma")

	s.separator(&first)
	assert.Equal(t, ",,", buf.String())
}

func TestJSONStream_ShortWriteReturnsError(t *testing.T) {
	w := &shortWriter{max: 2}
	s := newJSONStream(w)

	n, err := s.Write([]byte("hello world"))
	require.ErrorIs(t, err, io.ErrShortWrite)
	assert.Equal(t, 2, n)
	assert.ErrorIs(t, s.err, io.ErrShortWrite, "short write must set sticky error on stream")
}

func TestJSONStream_StickyErrorSuppressesFurtherWrites(t *testing.T) {
	wantErr := errors.New("underlying write error")
	w := &failingWriter{err: wantErr}
	s := newJSONStream(w)

	// Trigger initial error
	s.raw("start")
	require.ErrorIs(t, s.err, wantErr)

	// All subsequent operations should be no-ops and preserve the original error
	n, err := s.Write([]byte("more"))
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, wantErr)

	first := false
	s.raw("text")
	s.value("unwritten-value")
	s.key(&first, "unwritten-key")
	s.field(&first, "field", "val")

	assert.ErrorIs(t, s.err, wantErr)
}

func TestJSONStream_ValueEncodingFailureSetsStickyError(t *testing.T) {
	var buf bytes.Buffer
	s := newJSONStream(&buf)

	// Channels cannot be encoded to JSON
	unsupported := make(chan int)
	s.value(unsupported)

	require.Error(t, s.err)

	// Further writes must not change buffer
	bufLen := buf.Len()
	s.raw("trailing")
	assert.Equal(t, bufLen, buf.Len(), "raw write after encode error must be a no-op")
}
