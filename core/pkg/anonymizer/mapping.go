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

	// Hash prefix+value together, not value alone: the same raw value
	// mapped under two different prefixes (e.g. a namespace and a resource
	// name that happen to be identical strings) must not produce the same
	// hash suffix. Hashing value alone let that identical suffix leak
	// through the "<prefix>-<suffix>" pseudo-ID, letting an observer
	// correlate two differently-prefixed pseudo-IDs as sharing the same
	// original value even without knowing what that value was - exactly
	// the kind of cross-reference an anonymizer must not permit.
	hash := sha256.Sum256([]byte(key))
	pseudo := prefix + "-" + hex.EncodeToString(hash[:])[:8]

	m.data[key] = pseudo

	return pseudo
}
