package policytest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
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
// rule directory, it is returned as the sole result. Otherwise Discover is
// used to find rule directories among path's immediate children.
func DiscoverPath(path string) ([]RuleUnderTest, error) {
	dirs, err := ruledir.DiscoverPath(path)
	if err != nil {
		return nil, err
	}
	return withCases(dirs)
}

// Discover walks root looking for rule directories among its immediate
// children. It does not require a test/ subdirectory to exist, but a rule with
// no cases produces no CaseResults when run.
func Discover(root string) ([]RuleUnderTest, error) {
	dirs, err := ruledir.Discover(root)
	if err != nil {
		return nil, err
	}
	return withCases(dirs)
}

// withCases attaches the fixtures under each rule's test/ subdirectory.
func withCases(dirs []ruledir.Rule) ([]RuleUnderTest, error) {
	rules := make([]RuleUnderTest, 0, len(dirs))
	for _, dir := range dirs {
		cases, err := discoverCases(filepath.Join(dir.Dir, "test"))
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", dir.Name, err)
		}
		rules = append(rules, RuleUnderTest{
			Name:  dir.Name,
			Dir:   dir.Dir,
			Rule:  dir.Rule,
			Cases: cases,
		})
	}
	return rules, nil
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
