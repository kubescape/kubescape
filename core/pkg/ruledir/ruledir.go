// Package ruledir reads the on-disk rule layout shared by the repository's
// rules/ tree: a directory holding raw.rego next to rule.metadata.json.
package ruledir

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/kubescape/opa-utils/reporthandling"
)

const (
	RegoFileName     = "raw.rego"
	MetadataFileName = "rule.metadata.json"
)

// Rule is one rule directory and the policy it defines.
type Rule struct {
	Name string
	Dir  string
	Rule reporthandling.PolicyRule
}

// Is reports whether dir holds both files that make up a rule.
func Is(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, RegoFileName)); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, MetadataFileName))
	return err == nil
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

	metaRaw, err := os.ReadFile(filepath.Join(dir, MetadataFileName))
	if err != nil {
		return rule, fmt.Errorf("read %s: %w", MetadataFileName, err)
	}
	if err := json.Unmarshal(metaRaw, &rule); err != nil {
		return rule, fmt.Errorf("parse %s: %w", MetadataFileName, err)
	}

	regoRaw, err := os.ReadFile(filepath.Join(dir, RegoFileName))
	if err != nil {
		return rule, fmt.Errorf("read %s: %w", RegoFileName, err)
	}
	rule.Rule = string(regoRaw)

	return rule, nil
}
