package printer

import (
	"encoding/json"
	"io"
)

// jsonStream only frames objects and arrays; encoding/json still owns the
// encoding of every value. Keep large collections out of individual values.
type jsonStream struct {
	writer  io.Writer
	encoder *json.Encoder
	err     error
}

func newJSONStream(w io.Writer) *jsonStream {
	s := &jsonStream{writer: w}
	s.encoder = json.NewEncoder(s)
	return s
}

func (s *jsonStream) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	s.err = err
	return n, err
}

func (s *jsonStream) raw(text string) {
	if s.err == nil {
		_, s.err = io.WriteString(s, text)
	}
}

func (s *jsonStream) value(value any) {
	if s.err == nil {
		s.err = s.encoder.Encode(value)
	}
}

func (s *jsonStream) separator(first *bool) {
	if !*first {
		s.raw(",")
	}
	*first = false
}

func (s *jsonStream) key(first *bool, name string) {
	if s.err != nil {
		return
	}
	s.separator(first)
	// Strings cannot fail JSON encoding. Unlike strconv.Quote, this also
	// preserves JSON escaping for resource IDs used as object keys.
	key, _ := json.Marshal(name)
	s.raw(string(key) + ":")
}

func (s *jsonStream) field(first *bool, name string, value any) {
	s.key(first, name)
	s.value(value)
}
