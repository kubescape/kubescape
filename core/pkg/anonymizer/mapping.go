package anonymizer

import (
	"crypto/sha256"
	"encoding/hex"
)

type Mapping struct {
	data map[string]string
}

func NewMapping() *Mapping {
	return &Mapping{
		data: make(map[string]string),
	}
}

func (m *Mapping) GetOrCreate(prefix, value string) string {
	key := prefix + ":" + value

	if existing, ok := m.data[key]; ok {
		return existing
	}

	hash := sha256.Sum256([]byte(value))
	pseudo := prefix + "-" + hex.EncodeToString(hash[:])[:8]

	m.data[key] = pseudo

	return pseudo
}
