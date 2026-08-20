package cautils

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// IgnoreFileName is the optional file, read from the scan root, listing paths to
// keep out of a local scan.
const IgnoreFileName = ".kubescapeignore"

var (
	ErrEmptyIgnorePattern    = errors.New("exclusion pattern is empty")
	ErrInvalidIgnorePattern  = errors.New("invalid exclusion pattern")
	ErrUnusableIgnorePattern = errors.New("exclusion pattern carries no rule")
)

type ignoreRule struct {
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool
	// descendantPrefix is set for a "dir/**" pattern, which covers everything below
	// dir without covering dir itself, so a later "!dir/keep.yaml" can re-include.
	descendantPrefix string
}

// PathFilter keeps paths out of a local scan. Patterns follow gitignore syntax: "#"
// starts a comment, "!" re-includes, a trailing "/" restricts a pattern to directories,
// a leading or embedded "/" anchors it to the scan root, and "**" spans any number of
// directories. The last pattern that matches a path decides it, and a path below an
// excluded directory cannot be re-included.
//
// Two deliberate differences from git: one ignore file is read, at the scan root, not
// one per directory; and surrounding whitespace is trimmed, so an indented line applies.
//
// Helm charts, Kustomize configurations and Terraform modules are excluded whole, because
// their own renderers decide which files they read. A pattern naming a single file inside
// one of them has no effect unless it excludes the directory.
type PathFilter struct {
	root  string
	rules []ignoreRule
}

// NewPathFilter compiles patterns into a filter anchored at root, returning nil when no
// pattern carries a rule.
func NewPathFilter(root string, patterns []string) (*PathFilter, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	rules := make([]ignoreRule, 0, len(patterns))
	for _, pattern := range patterns {
		rule, ok, err := parseIgnoreRule(pattern)
		if err != nil {
			return nil, err
		}
		if ok {
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}

	return &PathFilter{root: filepath.Clean(absRoot), rules: rules}, nil
}

// NewScanPathFilter builds the filter for a scan of input, combining the ignore file at
// the scan root with the patterns given on the command line. Command line patterns are
// applied last so they can re-include what the ignore file excluded.
func NewScanPathFilter(input string, patterns []string, useIgnoreFile bool) (*PathFilter, error) {
	root := ignoreRoot(input)

	var combined []string
	if useIgnoreFile {
		filePatterns, err := LoadIgnoreFilePatterns(root)
		if err != nil {
			return nil, err
		}
		if err := ValidateIgnorePatterns(filePatterns); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(root, IgnoreFileName), err)
		}
		combined = append(combined, filePatterns...)
	}
	combined = append(combined, patterns...)
	if len(combined) == 0 {
		return nil, nil
	}

	return NewPathFilter(root, combined)
}

// ValidateIgnorePatterns returns the first pattern that does not compile.
func ValidateIgnorePatterns(patterns []string) error {
	for _, pattern := range patterns {
		if _, _, err := parseIgnoreRule(pattern); err != nil {
			return err
		}
	}
	return nil
}

// ValidateCommandLinePatterns is ValidateIgnorePatterns plus the checks that only make
// sense for a typed argument: a blank or commented pattern is a formatting choice in a
// file, but on the command line it is a mistake that would silently exclude nothing.
func ValidateCommandLinePatterns(patterns []string) error {
	for _, pattern := range patterns {
		_, ok, err := parseIgnoreRule(pattern)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %q is blank or a comment", ErrUnusableIgnorePattern, pattern)
		}
	}
	return nil
}

// LoadIgnoreFilePatterns reads the ignore file at root. A missing file is not an error.
func LoadIgnoreFilePatterns(root string) ([]string, error) {
	path := filepath.Join(root, IgnoreFileName)
	file, err := os.Open(path) // #nosec G304 -- the path is the ignore file at the user's own scan root
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		patterns = append(patterns, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	return patterns, nil
}

// Excluded reports whether path is kept out of the scan. Paths outside the filter root
// are never excluded.
func (f *PathFilter) Excluded(path string, isDir bool) bool {
	if f == nil || len(f.rules) == 0 {
		return false
	}

	relative, ok := f.relative(path)
	if !ok {
		return false
	}

	// relative[:i] is the ancestor at this level, relative[start:i] its own name.
	excluded := false
	start := 0
	for i := 0; i <= len(relative); i++ {
		if i < len(relative) && relative[i] != '/' {
			continue
		}
		isLeaf := i == len(relative)
		for _, rule := range f.rules {
			if rule.matches(relative[:i], relative[start:i], !isLeaf || isDir) {
				excluded = !rule.negate
			}
		}
		// Nothing below an excluded directory can be re-included.
		if excluded && !isLeaf {
			return true
		}
		start = i + 1
	}

	return excluded
}

// Patterns returns the compiled patterns, in the order they are applied.
func (f *PathFilter) Patterns() []string {
	if f == nil {
		return nil
	}
	patterns := make([]string, 0, len(f.rules))
	for _, rule := range f.rules {
		patterns = append(patterns, rule.String())
	}
	return patterns
}

// Root returns the directory the patterns are matched against.
func (f *PathFilter) Root() string {
	if f == nil {
		return ""
	}
	return f.root
}

func (f *PathFilter) relative(path string) (string, bool) {
	absolute := path
	if !filepath.IsAbs(absolute) {
		var err error
		if absolute, err = filepath.Abs(absolute); err != nil {
			return "", false
		}
	}

	relative, err := filepath.Rel(f.root, filepath.Clean(absolute))
	if err != nil {
		return "", false
	}
	relative = filepath.ToSlash(relative)
	if relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", false
	}

	return relative, true
}

func (r ignoreRule) matches(target, segment string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	subject := segment
	if r.anchored {
		subject = target
	}
	// "dir/**" covers what is below dir, not dir itself. The prefix can carry its own
	// glob metadata, so it has to be matched against the subject, not compared to it.
	if r.descendantPrefix != "" && globMatch(r.descendantPrefix, subject) {
		return false
	}
	return globMatch(r.pattern, subject)
}

func globMatch(pattern, subject string) bool {
	matched, err := doublestar.Match(pattern, subject)
	return err == nil && matched
}

func (r ignoreRule) String() string {
	var builder strings.Builder
	if r.negate {
		builder.WriteString("!")
	}
	if r.anchored {
		builder.WriteString("/")
	}
	builder.WriteString(r.pattern)
	if r.dirOnly {
		builder.WriteString("/")
	}
	return builder.String()
}

// parseIgnoreRule compiles a single line. The second return value is false for a blank
// line or a comment, which carry no rule.
func parseIgnoreRule(line string) (ignoreRule, bool, error) {
	pattern := strings.TrimSpace(line)
	if pattern == "" || strings.HasPrefix(pattern, "#") {
		return ignoreRule{}, false, nil
	}

	var rule ignoreRule
	if strings.HasPrefix(pattern, "!") {
		rule.negate = true
		pattern = strings.TrimSpace(pattern[1:])
	}
	if strings.HasSuffix(pattern, "/") {
		rule.dirOnly = true
		pattern = strings.TrimRight(pattern, "/")
	}
	pattern = strings.TrimPrefix(pattern, "./")
	if strings.HasPrefix(pattern, "/") {
		rule.anchored = true
		pattern = strings.TrimLeft(pattern, "/")
	} else if strings.Contains(pattern, "/") {
		rule.anchored = true
	}

	if pattern == "" {
		return ignoreRule{}, false, fmt.Errorf("%w: %q", ErrEmptyIgnorePattern, line)
	}
	if !doublestar.ValidatePattern(pattern) {
		return ignoreRule{}, false, fmt.Errorf("%w: %q", ErrInvalidIgnorePattern, line)
	}

	rule.pattern = pattern
	rule.descendantPrefix = descendantPrefix(rule)
	return rule, true, nil
}

// descendantPrefix returns what a "dir/**" pattern sits below, so the directory itself can
// be told apart from its contents. Repeated trailing "/**" collapse, the way git treats them.
// A prefix that matches any path at all leaves nothing to tell apart, so it carries no guard.
func descendantPrefix(rule ignoreRule) string {
	if !rule.anchored {
		return ""
	}
	prefix := rule.pattern
	for strings.HasSuffix(prefix, "/**") {
		prefix = strings.TrimSuffix(prefix, "/**")
	}
	if prefix == rule.pattern || prefix == "" || prefix == "**" {
		return ""
	}
	return prefix
}

// ignoreRoot resolves the directory a scan input is anchored at. A file or a glob is
// anchored at its parent directory, so patterns stay relative to the same place.

func ignoreRoot(input string) string {
	if input == "" {
		return "."
	}
	if clonedRepo := GetClonedPath(input); clonedRepo != "" {
		input = clonedRepo
	}
	if isDir(input) {
		return input
	}
	return literalDir(input)
}

// literalDir returns the deepest ancestor directory of path that carries no glob
// metadata, so "manifests/**/*.yaml" anchors at "manifests" rather than "manifests/**".
func literalDir(path string) string {
	dir := filepath.Dir(path)
	for hasGlobMeta(filepath.Base(dir)) {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return dir
}
