package pathparse

import (
	"errors"
	"fmt"
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
// ParsePath scans the string instead of splitting it, so a bracket or a quoted
// key is read as a unit and its contents never reach the "." rule.

// ErrMalformedPath reports a path outside the grammar ParsePath accepts.
var ErrMalformedPath = errors.New("malformed path")

// Segment is one step of a parsed path: a map key, optionally indexed when
// the path selects an element of a list at that key. Index is -1 when the
// segment names a map entry rather than a list element.
//
// An index belongs to the segment it indexes rather than standing alone as its
// own segment: "containers[0]" is one step, not two. Callers depend on that.
// The printer compares a field's parent segments positionally against the
// canonical location its Kubernetes schema defines, so splitting an index into
// a separate segment would shift every parent path by one and quietly unmatch
// every safe-field rule guarding redaction.
type Segment struct {
	Key   string
	Index int
}

// ParsePath splits a path into its segments, or reports ErrMalformedPath.
//
// The grammar is deliberately narrow:
//
//	path     = key { "." key | "[" bracket "]" }
//	key      = bare | '"' text '"' | "'" text "'"
//	bracket  = digits | bare-bracket | '"' text '"' | "'" text "'"
//
// An unquoted key holds only letters, digits, "_", "-" and "/" - plus "." when
// bracketed - which covers every path regolibrary emits. A quoted key -
// dot-quoted as in metadata.annotations."foo.bar/baz", or bracketed as in
// ['foo.bar/baz'] - runs to its closing quote and may hold anything else. Unquoted all-digit bracket
// contents are a list index and attach to the segment before them; anything
// else in a bracket is a map key and becomes its own segment. Quoting is how a
// rule says "key, not index", so data['0'] names the entry "0".
//
// Anything else is rejected rather than approximated: a character outside the
// key alphabet in an unquoted key (an unmatched "[", a space, a "*" wildcard),
// an unclosed bracket or quote, a stray "]", an empty or doubled ".", an empty
// bracket, an index with nothing to qualify, a second index on one segment, or
// text straight after a closing bracket or quote. Each of those used to be
// read as the nearest well-formed path, and that path is a real field: a
// location resolved for it points at a line of YAML the rule never named,
// with nothing to say it is a guess. A caller told the path is malformed can
// show no location instead.
//
// Assisted-remediation strings arrive as "<path>=<value>", so everything from
// the first "=" outside a bracket or quote is dropped first, along with one
// leading ".". An empty path yields no segments and no error.
func ParsePath(path string) ([]Segment, error) {
	original := path
	path = TruncateAtValueSeparator(path)
	if path == "" {
		return nil, nil
	}

	malformed := func(reason string) ([]Segment, error) {
		return nil, fmt.Errorf("%w %q: %s", ErrMalformedPath, original, reason)
	}

	var segments []Segment
	expectKey := true // at the start, or just past a "."
	afterDot := false

	for i := 0; i < len(path); {
		c := path[i]

		if expectKey {
			switch c {
			case '.':
				return malformed("empty segment")
			case ']':
				return malformed("unmatched ']'")
			case '[':
				if afterDot {
					return malformed("'[' directly after '.'")
				}
				contents, quoted, end, reason := readBracket(path, i)
				if reason != "" {
					return malformed(reason)
				}
				if _, isIndex := digitIndex(contents); isIndex && !quoted {
					return malformed("index with no key to qualify")
				}
				segments = append(segments, Segment{Key: contents, Index: -1})
				i = end + 1
			case '"', '\'':
				key, end, reason := readQuoted(path, i)
				if reason != "" {
					return malformed(reason)
				}
				segments = append(segments, Segment{Key: key, Index: -1})
				i = end + 1
			default:
				end := i
				for end < len(path) && isKeyChar(path[end]) {
					end++
				}
				if end == i {
					return malformed(fmt.Sprintf("unexpected %q", c))
				}
				segments = append(segments, Segment{Key: path[i:end], Index: -1})
				i = end
			}
			expectKey = false
			afterDot = false
			continue
		}

		switch c {
		case '.':
			if i == len(path)-1 {
				return malformed("trailing '.'")
			}
			expectKey = true
			afterDot = true
			i++
		case '[':
			contents, quoted, end, reason := readBracket(path, i)
			if reason != "" {
				return malformed(reason)
			}
			if index, isIndex := digitIndex(contents); isIndex && !quoted {
				last := &segments[len(segments)-1]
				if last.Index >= 0 {
					return malformed("second index on one segment")
				}
				last.Index = index
			} else {
				segments = append(segments, Segment{Key: contents, Index: -1})
			}
			i = end + 1
		default:
			return malformed(fmt.Sprintf("unexpected %q after a key", c))
		}
	}

	return segments, nil
}

// isKeyChar reports whether c may appear in an unquoted key: the characters
// Kubernetes field names and label, annotation and data keys are built from.
// A bracketed key may also hold "."; a bare one cannot, since "." separates.
//
// The set is closed on purpose. Every character outside it - a space, "[",
// "|", "=" - is one no real key contains, so a path carrying one unquoted is
// malformed. Accepting it as a key would let it miss, walk up, and report an
// ancestor's line as the finding's. A key that genuinely holds such a
// character can still be written quoted.
func isKeyChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_', c == '-', c == '/':
		return true
	}
	return false
}

// readBracket reads the bracket opening at open. It returns the contents with
// any quotes stripped, whether they were quoted, and the index of the closing
// bracket; or a reason the bracket is malformed.
//
// Whether the contents were quoted is reported separately because stripping the
// quotes discards the one signal that says a run of digits is a key. A quoted
// key is read to its closing quote first, so a "]" inside the quotes belongs to
// the key rather than closing the bracket.
func readBracket(path string, open int) (contents string, quoted bool, closing int, reason string) {
	start := open + 1
	if start < len(path) && (path[start] == '"' || path[start] == '\'') {
		key, end, reason := readQuoted(path, start)
		if reason != "" {
			return "", false, 0, reason
		}
		if end+1 >= len(path) || path[end+1] != ']' {
			return "", false, 0, "quoted key not followed by ']'"
		}
		return key, true, end + 1, ""
	}

	end := strings.IndexByte(path[start:], ']')
	if end < 0 {
		return "", false, 0, "unclosed '['"
	}
	contents = path[start : start+end]
	switch contents {
	case "":
		return "", false, 0, "empty '[]'"
	case "*":
		// yq reads "[*]" as an operator, not a key, and the resolver's evaluator
		// rejects it outright. Accepting it as a key named "*" would turn a
		// lookup that fails into a walk up to whatever encloses it.
		return "", false, 0, "unsupported '[*]'"
	}
	// The bracket ends at the first "]", so anything the key alphabet does not
	// allow is rejected here - including an unmatched "[", which would
	// otherwise make metadata.labels[app[foo] the key "app[foo", miss, and
	// walk up to the labels block. A key that really holds such a character
	// uses the quoted form, ['app[foo'].
	for i := 0; i < len(contents); i++ {
		if c := contents[i]; c != '.' && !isKeyChar(c) {
			return "", false, 0, fmt.Sprintf("unexpected %q inside '[]'", c)
		}
	}
	return contents, false, start + end, ""
}

// readQuoted reads a quoted key whose opening quote is at open, returning the
// key and the index of its closing quote, or a reason it is malformed. Keys
// are read verbatim: Kubernetes label and annotation keys cannot contain a
// quote, so there is no escape syntax to honour.
func readQuoted(path string, open int) (key string, closing int, reason string) {
	quote := path[open]
	end := strings.IndexByte(path[open+1:], quote)
	if end < 0 {
		return "", 0, "unclosed quote"
	}
	key = path[open+1 : open+1+end]
	if key == "" {
		return "", 0, "empty quoted key"
	}
	return key, open + 1 + end, ""
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

// TruncateAtValueSeparator drops the "=<value>" half of an assisted-remediation
// string, along with any leading ".".
//
// The split has to be on the first "=" that is not inside a bracket or a quoted
// key. Fix values routinely contain "=" themselves - the CIS control-plane
// rules emit "--anonymous-auth=false" - so a later separator must not be
// mistaken for the first, and a key holding an "=" must not be cut in half.
func TruncateAtValueSeparator(path string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(path); i++ {
		c := path[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
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
