package anonymizer

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// pseudoIDHashLength is the number of hex characters of the SHA-256 digest
// kept in a pseudo-ID suffix. 32 hex characters carry 128 bits, which puts a
// collision beyond reach for any realistic report.
//
// This is deliberately not a short digest: the suffix is the only thing that
// distinguishes one pseudonym from another, and transformSession (session.go)
// re-keys AllResources, ResourcesResult and the rest of the session maps by
// the transformed ID. Two distinct values sharing a suffix therefore do not
// merely look alike in the report - they collapse into a single map entry,
// silently dropping a resource. A 32-bit suffix reached that point at a
// birthday bound of only ~2^16 distinct values, well inside the range a
// single large cluster produces once names, namespaces, labels, annotations
// and source paths are counted together - all of which share one suffix
// space, because the hash is taken over the value alone (see GetOrCreate).
const pseudoIDHashLength = 32

type Mapping struct {
	data map[string]string // "prefix:value" -> pseudo-ID, the forward cache GetOrCreate reads/writes
	seen map[string]string // pseudo-ID -> the value that first produced it, kept only to detect a hash collision
}

func NewMapping() *Mapping {
	return &Mapping{
		data: make(map[string]string),
		seen: make(map[string]string),
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
	suffix := hex.EncodeToString(hash[:])[:pseudoIDHashLength]
	pseudo := prefix + "-" + suffix

	// A 128-bit suffix (see pseudoIDHashLength) puts a genuine SHA-256
	// collision far beyond the reach of any realistic report, but returning
	// a colliding pseudo-ID unchanged would merge two distinct resources
	// into one report entry - the exact failure that suffix width exists to
	// prevent - so detect it defensively rather than trust the odds alone.
	//
	// A hit in m.seen here can only be a genuine collision, never the
	// intentional same-value/different-prefix suffix sharing documented
	// above: that sharing ties suffixes together, not full pseudo-IDs, and
	// an identical (prefix, value) pair would already have returned via the
	// m.data lookup at the top of this function.
	//
	// Disambiguating trades away one property: if two colliding values are
	// never scanned together, each keeps the plain "<prefix>-<suffix>" form
	// across runs as documented; only the run where both happen to appear
	// gives the later one an appended counter, so this one pseudo-ID is not
	// guaranteed identical across every future report. That is an
	// acceptable trade for never silently merging two resources.
	for attempt := 1; ; attempt++ {
		if _, collided := m.seen[pseudo]; !collided {
			break
		}

		logger.L().Warning("anonymizer: pseudo-ID collision detected, disambiguating to avoid merging distinct resources",
			helpers.String("prefix", prefix), helpers.String("pseudo", pseudo))

		pseudo = prefix + "-" + suffix + "-" + strconv.Itoa(attempt)
	}

	m.data[key] = pseudo
	m.seen[pseudo] = value

	return pseudo
}
