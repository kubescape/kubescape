package policytest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/opaprocessor/cel"
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

const celPolicyFile = "policy.yaml"

// RuleUnderTest is a Rego or CEL rule with the cases under its test/ directory.
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
	rule, ok, err := loadRule(path)
	if err != nil {
		return nil, err
	}
	if ok {
		return []RuleUnderTest{rule}, nil
	}
	return Discover(path)
}

// Discover walks root looking for rule directories among its immediate
// children. It does not require a test/ subdirectory to exist, but a rule with
// no cases produces no CaseResults when run.
func Discover(root string) ([]RuleUnderTest, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", root, err)
	}
	var rules []RuleUnderTest
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rule, ok, err := loadRule(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		if ok {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func loadRule(dir string) (RuleUnderTest, bool, error) {
	regoRule, ok, err := ruledir.Load(dir)
	if err != nil {
		return RuleUnderTest{}, false, fmt.Errorf("rule %q: %w", dir, err)
	}
	rule := regoRule.Rule
	if !ok {
		policyPath := filepath.Join(dir, celPolicyFile)
		info, err := os.Stat(policyPath)
		if os.IsNotExist(err) {
			return RuleUnderTest{}, false, nil
		}
		if err != nil {
			return RuleUnderTest{}, false, fmt.Errorf("inspect policy %q: %w", policyPath, err)
		}
		if !info.Mode().IsRegular() {
			return RuleUnderTest{}, false, fmt.Errorf("policy %q: %w", policyPath, ruledir.ErrNotRegularFile)
		}
		rule, err = loadCELRule(policyPath)
		if err != nil {
			return RuleUnderTest{}, false, fmt.Errorf("policy %q: %w", policyPath, err)
		}
	}

	cases, err := discoverCases(filepath.Join(dir, "test"))
	if err != nil {
		return RuleUnderTest{}, false, fmt.Errorf("rule %q: %w", dir, err)
	}
	return RuleUnderTest{Name: filepath.Base(dir), Dir: dir, Rule: rule, Cases: cases}, true, nil
}

func loadCELRule(path string) (reporthandling.PolicyRule, error) {
	framework, err := getter.LoadCustomRules(path)
	if err != nil {
		return reporthandling.PolicyRule{}, err
	}
	if len(framework.Controls) != 1 {
		return reporthandling.PolicyRule{}, fmt.Errorf("expected one ValidatingAdmissionPolicy, found %d", len(framework.Controls))
	}
	rule := framework.Controls[0].Rules[0]
	policy, err := cel.ParseVAP([]byte(rule.Rule))
	if err != nil {
		return reporthandling.PolicyRule{}, err
	}
	if policy.TakesParams() {
		return reporthandling.PolicyRule{}, fmt.Errorf("policy test requires a ValidatingAdmissionPolicy without spec.paramKind")
	}
	return rule, nil
}

// FilterCases keeps only the cases whose "<rule>/<case>" name, the name policy
// test reports each case under, matches pattern. Rules left without a matching
// case are dropped, so a rule that has no cases at all is dropped as well. The
// input slice is not modified.
func FilterCases(rules []RuleUnderTest, pattern *regexp.Regexp) []RuleUnderTest {
	filtered := make([]RuleUnderTest, 0, len(rules))
	for _, rule := range rules {
		var cases []Case
		for _, c := range rule.Cases {
			if pattern.MatchString(rule.Name + "/" + c.Name) {
				cases = append(cases, c)
			}
		}
		if len(cases) == 0 {
			continue
		}
		rule.Cases = cases
		filtered = append(filtered, rule)
	}
	return filtered
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
