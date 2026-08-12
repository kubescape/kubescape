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

	// Deliberately hash value alone, not prefix+value: transformSession
	// (session.go) relies on the same raw value producing the same hash
	// suffix under different prefixes to preserve referential integrity for
	// name-based references that are not backed by a resource ID lookup -
	// e.g. a Secret's own name is transformed with prefix "res"
	// (session.go transformResourceMetadata) while the same name referenced
	// via imagePullSecrets or a ServiceAccount name is transformed
	// separately with prefix "ref"/"sa" (container.go). Hashing
	// prefix+value instead would give those two pseudonyms unrelated
	// suffixes, silently severing the ability to tell from a --hide report
	// alone that a pod pulls a given Secret or runs as a given
	// ServiceAccount - the report would still list both objects, just with
	// no visible connection between them.
	//
	// This does mean a value that happens to be reused across semantically
	// unrelated categories (e.g. a namespace named the same as a resource)
	// produces a matching suffix too, which lets an observer infer the two
	// values are equal without learning what either is. The cost is larger
	// than just those two values, though: because the suffix is derived
	// from value alone, it is a single identifier for that value shared
	// across every prefix in the whole report. Any one cleartext occurrence
	// of the value anywhere (e.g. container.go does not currently transform
	// spec.volumes, so a Secret/ConfigMap name used there stays in
	// cleartext even when the same name is anonymized via imagePullSecrets)
	// de-anonymizes every pseudonym sharing that suffix at once, not just
	// the one field it leaked from. That is a real, but still narrower than
	// it may look: the documented --hide threat model (docs/cli-reference.md)
	// already concedes that any individual pseudonym can be reversed by
	// hashing candidate values from a small or guessable set, so an
	// observer who can already recover "default" from "ns-<hash>" gains
	// little from cross-prefix suffix comparison for guessable values -
	// this channel mainly matters for values that are not guessable but do
	// leak in cleartext somewhere.
	//
	// A secret salt or HMAC key would reduce offline guessing, and a
	// per-run random key would additionally close this cross-prefix/
	// cross-leak channel entirely - but a per-run key also breaks the
	// documented property that identical values produce identical
	// pseudonyms across separate reports/runs. Neither a fixed nor a
	// per-run key removes the equality on its own; that requires
	// prefix/domain-separated hashing (i.e. going back to hashing
	// prefix+value), which is exactly what breaks the referential linkage
	// this function exists to preserve. That combined trade-off needs an
	// explicit decision, not a change made incidentally here.
	hash := sha256.Sum256([]byte(value))
	pseudo := prefix + "-" + hex.EncodeToString(hash[:])[:8]

	m.data[key] = pseudo

	return pseudo
}
