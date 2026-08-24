package policytest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/kubescape/opa-utils/reporthandling"
)

// Case is a single test fixture for a rule: a directory containing an
// input/ subdirectory of Kubernetes manifests and an expected.json file
// holding the []reporthandling.RuleResponse the rule must produce.
type Case struct {
	Name string
	Dir  string
}

// RuleUnderTest is a rule directory (raw.rego + rule.metadata.json) together
// with the test cases discovered under its test/ subdirectory.
type RuleUnderTest struct {
	Name  string
	Dir   string
	Rule  reporthandling.PolicyRule
	Cases []Case
}

// DiscoverPath resolves path to the rules under test. If path is itself a
// rule directory (contains raw.rego and rule.metadata.json), it is returned
// as the sole result. Otherwise Discover is used to find rule directories
// among path's immediate children.
func DiscoverPath(path string) ([]RuleUnderTest, error) {
	if rule, ok, err := discoverRuleDir(path); err != nil {
		return nil, err
	} else if ok {
		return []RuleUnderTest{rule}, nil
	}
	return Discover(path)
}

// Discover walks root looking for rule directories: any immediate child
// directory that contains both raw.rego and rule.metadata.json. It does not
// require a test/ subdirectory to exist, but a rule with no cases produces
// no CaseResults when run.
func Discover(root string) ([]RuleUnderTest, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", root, err)
	}

	var rules []RuleUnderTest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		rule, ok, err := discoverRuleDir(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", e.Name(), err)
		}
		if ok {
			rules = append(rules, rule)
		}
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, nil
}

// discoverRuleDir loads dir as a rule directory. ok is false, with no error,
// when dir does not contain both raw.rego and rule.metadata.json.
func discoverRuleDir(dir string) (RuleUnderTest, bool, error) {
	regoPath := filepath.Join(dir, "raw.rego")
	metaPath := filepath.Join(dir, "rule.metadata.json")
	if _, err := os.Stat(regoPath); err != nil {
		return RuleUnderTest{}, false, nil
	}
	if _, err := os.Stat(metaPath); err != nil {
		return RuleUnderTest{}, false, nil
	}

	rule, err := loadRule(regoPath, metaPath)
	if err != nil {
		return RuleUnderTest{}, false, err
	}

	cases, err := discoverCases(filepath.Join(dir, "test"))
	if err != nil {
		return RuleUnderTest{}, false, err
	}

	return RuleUnderTest{
		Name:  filepath.Base(dir),
		Dir:   dir,
		Rule:  rule,
		Cases: cases,
	}, true, nil
}

func loadRule(regoPath, metaPath string) (reporthandling.PolicyRule, error) {
	var rule reporthandling.PolicyRule

	metaRaw, err := os.ReadFile(metaPath)
	if err != nil {
		return rule, fmt.Errorf("read rule.metadata.json: %w", err)
	}
	if err := json.Unmarshal(metaRaw, &rule); err != nil {
		return rule, fmt.Errorf("parse rule.metadata.json: %w", err)
	}

	regoRaw, err := os.ReadFile(regoPath)
	if err != nil {
		return rule, fmt.Errorf("read raw.rego: %w", err)
	}
	rule.Rule = string(regoRaw)

	return rule, nil
}

func discoverCases(testDir string) ([]Case, error) {
	entries, err := os.ReadDir(testDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read test dir: %w", err)
	}

	var cases []Case
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cases = append(cases, Case{Name: e.Name(), Dir: filepath.Join(testDir, e.Name())})
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })
	return cases, nil
}
