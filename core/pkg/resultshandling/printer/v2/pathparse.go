package printer

import (
	"strconv"
	"strings"
)

// Path parsing for the paths regolibrary rules emit.
//
// A rule reports a finding against a field by its path through the resource:
// "spec.template.spec.containers[0].image". Splitting that on "." is right up
// until a key contains a "." of its own, which Kubernetes label and annotation
// keys routinely do - "metadata.labels[pod-security.kubernetes.io/enforce]"
// splits into six meaningless fragments. Surveying every path the rules emit
// (their test fixtures, so the substituted output rather than the sprintf
// templates) found ten such paths, in two shapes:
//
//   - keys carrying dots, which a "."-split shatters:
//     metadata.labels[pod-security.kubernetes.io/enforce]
//     spec.template.metadata.labels[app.kubernetes.io/name]
//     metadata.annotations['service.beta.kubernetes.io/aws-load-balancer-ssl-cert']
//
//   - plain keys, where the bracket is dropped instead:
//     metadata.labels[app]
//     spec.template.metadata.labels[YOUR_LABEL]
//
// The second shape is the more dangerous of the two. Nothing shatters, so the
// path still resolves - but to the whole labels map rather than the one key
// asked for, which reads as a successful lookup of the wrong thing.
//
// parsePath scans the string instead of splitting it, so a bracket is read as a
// unit and its contents never reach the "." rule.

// pathSegment is one step of a parsed path: a map key, optionally indexed when
// the path selects an element of a list at that key.
//
// An index belongs to the segment it indexes rather than standing alone as its
// own segment: "containers[0]" is one step, not two. Callers depend on that.
// matchesSafeField compares a field's parent segments positionally against the
// canonical location its Kubernetes schema defines, so splitting an index into
// a separate segment would shift every parent path by one and quietly unmatch
// every safe-field rule guarding redaction.

// parsePath splits a path into its segments.
//
// A bracket holds either a list index or a map key. All-digit contents are read
// as an index and attached to the preceding segment; anything else is a key and
// becomes a segment of its own, with surrounding quotes stripped. That keeps
// "containers[0].image" at two segments while giving "labels[app]" three, which
// is what each one means.
//
// Assisted-remediation strings arrive as "<path>=<value>" and only the path is
// parseable, so everything from the first "=" outside a bracket is dropped. A
// "=" inside a bracket is part of the key and survives.
//
// Malformed input is parsed as far as it makes sense rather than rejected:
// these paths come from rules the scanner does not control, and a path that
// resolves to nothing is already handled everywhere downstream. An unclosed
// bracket takes the rest of the string as its contents; empty segments from a
// leading or doubled "." are skipped.
func parsePath(path string) []pathSegment {
	path = truncateAtValueSeparator(path)

	var (
		segments []pathSegment
		key      strings.Builder
		started  bool
	)

	// flush ends the segment being read. started tracks whether a segment is
	// open at all, so that "a..b" skips the empty middle rather than emitting
	// a segment with an empty key, while "labels[app]" can still close the
	// bracket key as its own segment.
	flush := func() {
		if !started {
			return
		}
		segments = append(segments, pathSegment{key: key.String(), index: -1})
		key.Reset()
		started = false
	}

	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '.':
			flush()
		case '[':
			contents, quoted, next := readBracket(path, i)
			i = next

			// Quoting is how a rule says "this is a key, not an index", so a
			// quoted run of digits stays a key: data['0'] selects the Secret
			// entry named "0", not the first element of a list.
			if index, ok := digitIndex(contents); ok && !quoted {
				switch {
				case started:
					// The index qualifies the segment being read.
					segments = append(segments, pathSegment{key: key.String(), index: index})
					key.Reset()
					started = false
				case len(segments) > 0 && segments[len(segments)-1].index < 0:
					// The index follows a segment that is already closed - a
					// bracketed key, as in annotations[foo.bar/list][2]. It
					// qualifies that one. Dropping it would resolve the path
					// to the whole list, the same "succeeds against the wrong
					// thing" failure that reading brackets exists to end.
					segments[len(segments)-1].index = index
				}
				// Anything else has nothing to qualify: a leading "[0]", or a
				// second index on an already-indexed segment.
				continue
			}

			flush()
			if contents != "" {
				segments = append(segments, pathSegment{key: contents, index: -1})
			}
		default:
			key.WriteByte(path[i])
			started = true
		}
	}
	flush()

	return segments
}

// readBracket reads the contents of the bracket opening at open. It returns the
// contents with any surrounding quotes stripped, whether they were quoted, and
// the index of the closing bracket. An unclosed bracket yields the rest of the
// string, so a malformed path degrades to a lookup that finds nothing rather
// than to a panic.
//
// Whether the contents were quoted is reported separately because stripping the
// quotes discards the one signal that says a run of digits is a key.
func readBracket(path string, open int) (contents string, quoted bool, closing int) {
	end := strings.IndexByte(path[open+1:], ']')
	if end < 0 {
		contents, quoted = unquote(path[open+1:])
		return contents, quoted, len(path) - 1
	}
	end += open + 1
	contents, quoted = unquote(path[open+1 : end])
	return contents, quoted, end
}

// unquote strips one layer of matching single or double quotes, which rules use
// for keys that would otherwise be ambiguous: metadata.annotations['%v'].
func unquote(s string) (string, bool) {
	if len(s) < 2 {
		return s, false
	}
	if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
		return s[1 : len(s)-1], true
	}
	return s, false
}

// digitIndex reports the list index a bracket's contents name, if the contents
// are a plain run of digits.
//
// The digits are checked explicitly rather than left to strconv.Atoi, which
// also accepts a sign: "[+0]" is not a list index any rule would write, and
// reading it as one would silently resolve the path to an element. This matches
// how isContainerEnvValue reads env[N] in pathvalue.go.
func digitIndex(contents string) (int, bool) {
	if contents == "" {
		return 0, false
	}
	for i := 0; i < len(contents); i++ {
		if contents[i] < '0' || contents[i] > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(contents)
	if err != nil {
		// Only reachable for a run of digits too long for an int.
		return 0, false
	}
	return index, true
}

// truncateAtValueSeparator drops the "=<value>" half of an assisted-remediation
// string, along with any leading ".".
//
// The split has to be on the first "=" that is not inside a bracket. Fix values
// routinely contain "=" themselves - the CIS control-plane rules emit
// "--anonymous-auth=false" - so a later separator must not be mistaken for the
// first, and an annotation key holding an "=" must not be cut in half.
func truncateAtValueSeparator(path string) string {
	depth := 0
	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth == 0 {
				return strings.TrimPrefix(path[:i], ".")
			}
		}
	}
	return strings.TrimPrefix(path, ".")
}
