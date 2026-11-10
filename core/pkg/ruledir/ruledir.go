// Package ruledir reads the on-disk rule layout shared by the repository's
// rules/ tree: a directory holding raw.rego next to rule.metadata.json.
package ruledir

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/kubescape/opa-utils/reporthandling"
)

const (
	RegoFileName     = "raw.rego"
	MetadataFileName = "rule.metadata.json"

	// maxRuleFileBytes caps how much of a rule file is read (32 MiB), matching
	// cautils.DefaultMaxFileSize, so an oversized input cannot exhaust memory
	// (CWE-400). It is not imported from cautils to keep this package free of
	// that dependency.
	maxRuleFileBytes int64 = 32 * 1024 * 1024
)

var (
	// ErrNotRegularFile is returned when a rule file is not a regular file.
	ErrNotRegularFile = errors.New("rule file is not a regular file")
	// ErrFileTooLarge is returned when a rule file exceeds the maximum size.
	ErrFileTooLarge = errors.New("rule file exceeds maximum size limit")
)

// Rule is one rule directory and the policy it defines.
type Rule struct {
	Name string
	Dir  string
	Rule reporthandling.PolicyRule
}

// Is reports whether dir holds both files that make up a rule.
// Both must be regular files: a FIFO, device or directory under either name is
// not a rule.
func Is(dir string) bool {
	return isRegularFile(filepath.Join(dir, RegoFileName)) &&
		isRegularFile(filepath.Join(dir, MetadataFileName))
}

// isRegularFile reports whether path opens as a regular file. The type is read
// from the opened descriptor, and O_NONBLOCK keeps opening a FIFO from waiting
// for a writer.
func isRegularFile(path string) bool {
	file, err := openRegular(path)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

// openRegular opens path for reading and rejects anything but a regular file.
// The check is made on the opened descriptor so a path swapped after an earlier
// look cannot slip past. O_NONBLOCK keeps opening a FIFO from waiting for a
// writer; it has no effect on a regular file.
func openRegular(path string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %q (%s)", ErrNotRegularFile, path, info.Mode().Type())
	}
	return file, nil
}

// ReadFile returns the contents of the rule file at path. It rejects anything
// but a regular file, and a file larger than 32 MiB, rather than reading it.
func ReadFile(path string) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// One byte past the limit tells a file of exactly the limit from a longer
	// one, which a plain limit would silently truncate.
	data, err := io.ReadAll(io.LimitReader(file, maxRuleFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRuleFileBytes {
		return nil, fmt.Errorf("%w: %q exceeds the %d byte limit", ErrFileTooLarge, path, maxRuleFileBytes)
	}
	return data, nil
}

// Load reads dir as a rule directory. ok is false, with no error, when dir is
// not one.
func Load(dir string) (Rule, bool, error) {
	if !Is(dir) {
		return Rule{}, false, nil
	}

	rule, err := loadPolicyRule(dir)
	if err != nil {
		return Rule{}, false, err
	}

	return Rule{
		Name: filepath.Base(dir),
		Dir:  dir,
		Rule: rule,
	}, true, nil
}

// Discover returns the rule directories among root's immediate children,
// ordered by name so callers produce stable output.
func Discover(root string) ([]Rule, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", root, err)
	}

	var rules []Rule
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rule, ok, err := Load(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", entry.Name(), err)
		}
		if ok {
			rules = append(rules, rule)
		}
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, nil
}

// DiscoverPath resolves path to rule directories, accepting either a single
// rule directory or a parent holding several.
func DiscoverPath(path string) ([]Rule, error) {
	if rule, ok, err := Load(path); err != nil {
		return nil, err
	} else if ok {
		return []Rule{rule}, nil
	}
	return Discover(path)
}

func loadPolicyRule(dir string) (reporthandling.PolicyRule, error) {
	var rule reporthandling.PolicyRule

	metaRaw, err := ReadFile(filepath.Join(dir, MetadataFileName))
	if err != nil {
		return rule, fmt.Errorf("read %s: %w", MetadataFileName, err)
	}
	if err := json.Unmarshal(metaRaw, &rule); err != nil {
		return rule, fmt.Errorf("parse %s: %w", MetadataFileName, err)
	}

	regoRaw, err := ReadFile(filepath.Join(dir, RegoFileName))
	if err != nil {
		return rule, fmt.Errorf("read %s: %w", RegoFileName, err)
	}
	rule.Rule = string(regoRaw)

	return rule, nil
}
