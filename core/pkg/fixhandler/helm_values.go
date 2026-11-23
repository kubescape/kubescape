package fixhandler

import (
	"bytes"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"gopkg.in/yaml.v3"
)

// CorrelatedValueFix links a rule-suggested FixPath to a static .Values key traced from the template.
type CorrelatedValueFix struct {
	ValuesPath string // e.g. "securityContext.readOnlyRootFilesystem"
	Value      string // e.g. "true"
	FixPath    string // original FixPath, e.g. "spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem"
}

// stripBracketIndices removes bracketed list indices like "[0]" from a path.
func stripBracketIndices(path string) string {
	var sb strings.Builder
	inBracket := false
	for _, ch := range path {
		if ch == '[' {
			inBracket = true
			continue
		}
		if ch == ']' {
			inBracket = false
			continue
		}
		if !inBracket {
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

// isContainerListSegment reports whether a path segment is one of a pod spec's
// container lists: containers, initContainers or ephemeralContainers. A fix
// under any of them is container-scoped, so it must not be matched to a
// pod-level .Values key.
func isContainerListSegment(seg string) bool {
	switch strings.ToLower(seg) {
	case "containers", "initcontainers", "ephemeralcontainers":
		return true
	}
	return false
}

// cleanValuesPath removes leading ".Values." or "." from candidate values path.
func cleanValuesPath(vp string) string {
	vpClean := strings.TrimPrefix(strings.TrimSpace(vp), ".Values.")
	return strings.TrimPrefix(vpClean, ".")
}

// CorrelateFixPathsWithValues matches concrete rule FixPaths with candidate .Values.* keys
// statically traced from the Helm template.
// A match requires a minimum of two matching trailing segments from the leaf up.
// Single-segment candidates (e.g. bare "privileged" or "enabled") are considered ambiguous
// and remain plain candidates. Container-scoped fixes do not match pod-scoped candidates.
// Conflicting proposed values for the same ValuesPath are excluded from correlation.
func CorrelateFixPathsWithValues(fixPaths []armotypes.FixPath, candidateValuesPaths []string) []CorrelatedValueFix {
	type proposedEntry struct {
		val        string
		fixPath    string
		matchCount int
	}

	proposed := make(map[string]proposedEntry)
	conflicted := make(map[string]bool)

	for _, fp := range fixPaths {
		if fp.Path == "" {
			continue
		}
		cleaned := stripBracketIndices(fp.Path)
		parts := strings.Split(cleaned, ".")
		if len(parts) < 2 {
			continue
		}

		isContainerFix := false
		for _, p := range parts {
			if isContainerListSegment(p) {
				isContainerFix = true
				break
			}
		}

		for _, vp := range candidateValuesPaths {
			vpClean := cleanValuesPath(vp)
			if vpClean == "" {
				continue
			}
			vParts := strings.Split(vpClean, ".")
			// Require at least two segments in the candidate (single-segment candidates are ambiguous)
			if len(vParts) < 2 {
				continue
			}

			// If it's a container-scoped fix, anchor away from pod-level securityContext candidates
			if isContainerFix {
				hasPodAnchor := false
				for _, seg := range vParts {
					segLower := strings.ToLower(seg)
					if strings.HasPrefix(segLower, "podsecurity") || segLower == "pod" {
						hasPodAnchor = true
						break
					}
				}
				if hasPodAnchor {
					continue
				}
			}

			// Count matching trailing segments from the leaf upwards
			matchCount := 0
			for m := 1; m <= len(vParts) && m <= len(parts); m++ {
				if strings.EqualFold(vParts[len(vParts)-m], parts[len(parts)-m]) {
					matchCount++
				} else {
					break
				}
			}

			// Must match at least two trailing segments
			if matchCount < 2 {
				continue
			}

			if prev, exists := proposed[vpClean]; exists {
				if prev.val != fp.Value {
					conflicted[vpClean] = true
				} else if matchCount > prev.matchCount {
					proposed[vpClean] = proposedEntry{
						val:        fp.Value,
						fixPath:    fp.Path,
						matchCount: matchCount,
					}
				}
			} else {
				proposed[vpClean] = proposedEntry{
					val:        fp.Value,
					fixPath:    fp.Path,
					matchCount: matchCount,
				}
			}
		}
	}

	var correlated []CorrelatedValueFix
	seen := make(map[string]bool)
	for _, vp := range candidateValuesPaths {
		vpClean := cleanValuesPath(vp)
		if conflicted[vpClean] || seen[vpClean] {
			continue
		}
		if entry, ok := proposed[vpClean]; ok {
			seen[vpClean] = true
			correlated = append(correlated, CorrelatedValueFix{
				ValuesPath: vpClean,
				Value:      entry.val,
				FixPath:    entry.fixPath,
			})
		}
	}

	return correlated
}

// GenerateProposedValuesYAML constructs a clean YAML snippet from correlated .Values fixes
// that users can inspect or directly add to their values.yaml file.
func GenerateProposedValuesYAML(correlated []CorrelatedValueFix) (string, error) {
	if len(correlated) == 0 {
		return "", nil
	}
	root := make(map[string]interface{})
	for _, c := range correlated {
		parts := strings.Split(c.ValuesPath, ".")
		curr := root
		for i, part := range parts {
			if i == len(parts)-1 {
				curr[part] = parseFixValue(c.Value)
			} else {
				if next, ok := curr[part].(map[string]interface{}); ok {
					curr = next
				} else {
					nextMap := make(map[string]interface{})
					curr[part] = nextMap
					curr = nextMap
				}
			}
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}
