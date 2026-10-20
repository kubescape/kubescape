package k8scveindex

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type semver struct{ major, minor, patch int }

func (v semver) compare(o semver) int {
	if v.major != o.major {
		return v.major - o.major
	}
	if v.minor != o.minor {
		return v.minor - o.minor
	}
	return v.patch - o.patch
}

func (v semver) nextMinor() semver { return semver{v.major, v.minor + 1, 0} }

// versionRange is a version interval. A nil From or To leaves that side open.
type versionRange struct {
	From        *semver
	To          *semver
	ToInclusive bool
}

func (r versionRange) contains(v semver) bool {
	if r.From != nil && v.compare(*r.From) < 0 {
		return false
	}
	if r.To != nil {
		c := v.compare(*r.To)
		return c < 0 || (c == 0 && r.ToInclusive)
	}
	return true
}

const versionPattern = `v?\d+\.\d+(?:\.\d+)?`

var (
	affectedHeader = regexp.MustCompile(`(?i)^(?:#+\s*|\*\*)affected versions\b`)
	fixedHeader    = regexp.MustCompile(`(?i)^(?:#+\s*|\*\*)fixed versions?\b`)
	anyHeader      = regexp.MustCompile(`^(?:#+\s|\*\*[^*]+\*\*\s*:?\s*$)`)
	affectedLine   = regexp.MustCompile(`^(?:[-*]\s*)?(?i:kubernetes\s+)?([a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*)*):?\s+(.+?)\s*(?:\([^)]*\))?$`)
	fixedLine      = regexp.MustCompile(`^(?:[-*]\s*)?(?i:kubernetes\s+)?([a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*)*):?\s+(?:>=\s*)?v?(\d+\.\d+\.\d+)\+?(?:\s|$)`)
	boundRange     = regexp.MustCompile(`^(<=|>=|<|>|=)\s*(` + versionPattern + `)$`)
	spanRange      = regexp.MustCompile(`^(` + versionPattern + `)\s*(?:\\?-|to)\s*(` + versionPattern + `)$`)
	exactRange     = regexp.MustCompile(`^(` + versionPattern + `)$`)
)

// parseVersion parses a feed version. Minor-only versions such as "v1.30"
// report full=false and mean the whole minor series.
func parseVersion(s string) (v semver, full bool, err error) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) < 2 || len(parts) > 3 {
		return semver{}, false, fmt.Errorf("invalid version %q", s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if nums[i], err = strconv.Atoi(p); err != nil {
			return semver{}, false, fmt.Errorf("invalid version %q", s)
		}
	}
	return semver{nums[0], nums[1], nums[2]}, len(parts) == 3, nil
}

func parseRange(s string) (versionRange, error) {
	if m := boundRange.FindStringSubmatch(s); m != nil {
		v, full, err := parseVersion(m[2])
		if err != nil {
			return versionRange{}, err
		}
		switch {
		case m[1] == "=":
			return exact(v, full), nil
		case m[1] == ">=" || (m[1] == ">" && !full):
			if m[1] == ">" {
				v = v.nextMinor()
			}
			return versionRange{From: &v}, nil
		case m[1] == ">":
			v.patch++
			return versionRange{From: &v}, nil
		case !full:
			if m[1] == "<=" {
				v = v.nextMinor()
			}
			return versionRange{To: &v}, nil
		default:
			return versionRange{To: &v, ToInclusive: m[1] == "<="}, nil
		}
	}
	if m := spanRange.FindStringSubmatch(s); m != nil {
		from, _, err := parseVersion(m[1])
		if err != nil {
			return versionRange{}, err
		}
		to, full, err := parseVersion(m[2])
		if err != nil {
			return versionRange{}, err
		}
		if !full {
			to = to.nextMinor()
		}
		if to.compare(from) < 0 || (!full && to.compare(from) == 0) {
			return versionRange{}, fmt.Errorf("reversed range %q", s)
		}
		return versionRange{From: &from, To: &to, ToInclusive: full}, nil
	}
	if m := exactRange.FindStringSubmatch(s); m != nil {
		v, full, err := parseVersion(m[1])
		if err != nil {
			return versionRange{}, err
		}
		return exact(v, full), nil
	}
	return versionRange{}, fmt.Errorf("unrecognized range %q", s)
}

func exact(v semver, full bool) versionRange {
	if !full {
		to := v.nextMinor()
		return versionRange{From: &v, To: &to}
	}
	return versionRange{From: &v, To: &v, ToInclusive: true}
}

// section returns the non-empty lines under the first heading matching
// header, or false when the entry has no such heading.
func section(content string, header *regexp.Regexp) ([]string, bool) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	start := slices.IndexFunc(lines, func(l string) bool { return header.MatchString(strings.TrimSpace(l)) })
	if start < 0 {
		return nil, false
	}
	var section []string
	for _, l := range lines[start+1:] {
		l = strings.TrimSpace(l)
		if anyHeader.MatchString(l) {
			break
		}
		if l != "" {
			section = append(section, l)
		}
	}
	return section, true
}

// parseAffected maps each component to its affected ranges. Any line it
// cannot attribute to a named component fails the whole section, so an entry
// is either fully understood or left unattributed.
func parseAffected(lines []string) (map[string][]versionRange, error) {
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty affected versions section")
	}
	affected := map[string][]versionRange{}
	for _, line := range lines {
		m := affectedLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("unrecognized line %q", line)
		}
		r, err := parseRange(m[2])
		if err != nil {
			return nil, err
		}
		for _, c := range strings.Split(m[1], "/") {
			if c == "kubernetes" {
				return nil, fmt.Errorf("no component named in %q", line)
			}
			affected[c] = append(affected[c], r)
		}
	}
	for _, ranges := range affected {
		if err := scopeUpperBounds(ranges); err != nil {
			return nil, err
		}
	}
	return affected, nil
}

// parseFixed maps each component to the releases a "Fixed Versions" section
// names. Lines without a component and full release, such as "master" or
// prose, are skipped.
func parseFixed(lines []string) map[string][]semver {
	fixed := map[string][]semver{}
	for _, line := range lines {
		m := fixedLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v, _, err := parseVersion(m[2])
		if err != nil {
			continue
		}
		for _, c := range strings.Split(m[1], "/") {
			if c != "kubernetes" {
				fixed[c] = append(fixed[c], v)
			}
		}
	}
	return fixed
}

// scopeUpperBounds handles entries that list one "<= vX.Y.Z" line per
// supported minor, such as "<= v1.28.0" and "<= v1.27.4". Each of those only
// covers its own minor series; only the lowest stays open below. An exclusive
// "< vX.Y.0" covers the X.(Y-1) series only when no other bound does, so it
// cannot re-include patches another line marks as fixed.
func scopeUpperBounds(ranges []versionRange) error {
	var upper []int
	covered := map[[2]int]bool{}
	for i, r := range ranges {
		switch {
		case r.To == nil:
		case r.From == nil:
			upper = append(upper, i)
			if !isSeriesStart(r) {
				covered[[2]int{r.To.major, r.To.minor}] = true
			}
		case r.From.major == r.To.major:
			last := r.To.minor
			if isSeriesStart(r) {
				last--
			}
			for minor := r.From.minor; minor <= last; minor++ {
				covered[[2]int{r.From.major, minor}] = true
			}
		}
	}
	if len(upper) < 2 {
		return nil
	}
	slices.SortFunc(upper, func(a, b int) int { return ranges[a].To.compare(*ranges[b].To) })
	for _, i := range upper[1:] {
		to := *ranges[i].To
		from := semver{to.major, to.minor, 0}
		if isSeriesStart(ranges[i]) {
			if to.minor == 0 {
				return fmt.Errorf("cannot scope < %d.0.0 to a minor series", to.major)
			}
			if !covered[[2]int{to.major, to.minor - 1}] {
				from.minor--
			}
		}
		ranges[i].From = &from
	}
	return nil
}

func isSeriesStart(r versionRange) bool {
	return !r.ToInclusive && r.To.patch == 0
}
