package getter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
	"github.com/kubescape/opa-utils/reporthandling"
)

const customControlPrefix = "custom-"

// A control's base score is what every severity consumer reads: the report's
// severity column, --min-severity/--max-severity and the --severity-threshold
// gate. A control that declares none scores 0, which opa-utils buckets as
// "Unknown" severity, and the threshold gate fails closed on unknown severity -
// so a custom rule without a base score would fail every --severity-threshold
// run regardless of what it checks. Default to the middle of the 1-10 range
// ("Medium"), and let a rule state its own severity in its Rego source.
const (
	baseScoreAnnotation        = "@baseScore"
	defaultCustomRuleBaseScore = 5.0
	minCustomRuleBaseScore     = 1.0
	maxCustomRuleBaseScore     = 10.0
)

// LoadCustomRules builds a synthetic framework from user-authored rules under
// path. Two layouts are accepted and may be mixed in one directory:
//
//   - a rule directory holding raw.rego next to rule.metadata.json, the layout
//     used by this repository's rules/ tree and by `kubescape policy test`
//   - a bare .rego file, whose rule is matched against every resource kind
//
// Either layout may declare the rule's severity with a "# @baseScore <1-10>"
// comment in its Rego source; without one the rule is Medium.
//
// An empty path is not an error and returns a nil framework.
func LoadCustomRules(path string) (*reporthandling.Framework, error) {
	if path == "" {
		return nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("custom rules path %q: %w", path, err)
	}

	if !info.IsDir() {
		if !strings.HasSuffix(path, ".rego") {
			return nil, fmt.Errorf("custom rules path %q is not a .rego file or directory", path)
		}
		control, err := controlFromRegoFile(path)
		if err != nil {
			return nil, err
		}
		return customFramework([]reporthandling.Control{control}), nil
	}

	// A path that is itself a rule directory describes exactly one rule; its
	// raw.rego must not also be picked up as a bare .rego file below.
	if rule, ok, err := ruledir.Load(path); err != nil {
		return nil, err
	} else if ok {
		control, err := controlFromRuleDir(rule)
		if err != nil {
			return nil, err
		}
		return customFramework([]reporthandling.Control{control}), nil
	}

	ruleDirs, err := ruledir.Discover(path)
	if err != nil {
		return nil, err
	}

	controls := make([]reporthandling.Control, 0, len(ruleDirs))
	for _, rule := range ruleDirs {
		control, err := controlFromRuleDir(rule)
		if err != nil {
			return nil, err
		}
		controls = append(controls, control)
	}

	files, err := regoFilesIn(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		control, err := controlFromRegoFile(file)
		if err != nil {
			return nil, err
		}
		controls = append(controls, control)
	}

	if len(controls) == 0 {
		return nil, fmt.Errorf("no custom rules found in %q: expected .rego files, or rule directories containing %s and %s",
			path, ruledir.RegoFileName, ruledir.MetadataFileName)
	}
	if err := rejectDuplicateControls(controls); err != nil {
		return nil, err
	}

	return customFramework(controls), nil
}

// rejectDuplicateControls guards the one collision the two layouts allow: a
// rule directory and a .rego file sharing a name resolve to the same control
// ID, and results are keyed by that ID, so one rule would be dropped from the
// report without a word.
func rejectDuplicateControls(controls []reporthandling.Control) error {
	seen := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		if _, duplicate := seen[control.ControlID]; duplicate {
			name := strings.TrimPrefix(control.ControlID, customControlPrefix)
			return fmt.Errorf("custom rule %q is defined twice: as a %s/%s directory and as %s.rego; rename one of them",
				name, name, ruledir.RegoFileName, name)
		}
		seen[control.ControlID] = struct{}{}
	}
	return nil
}

// regoFilesIn lists the bare .rego files directly under dir. Rule directories
// are skipped here because DiscoverPath already claimed them.
func regoFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read custom rules directory %q: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}

	// ReadDir is unordered; sort for stable control IDs and reports.
	sort.Strings(files)
	return files, nil
}

// controlFromRuleDir keeps the rule's declared match selectors, so it is only
// evaluated against the kinds it targets instead of every collected resource.
func controlFromRuleDir(rule ruledir.Rule) (reporthandling.Control, error) {
	policy := rule.Rule
	if policy.Name == "" {
		policy.Name = rule.Name
	}
	if len(policy.Match) == 0 {
		policy.Match = matchAllKinds()
	}
	if policy.RuleLanguage == "" {
		policy.RuleLanguage = reporthandling.RegoLanguage
	}

	baseScore, err := baseScoreFromRego(policy.Rule)
	if err != nil {
		return reporthandling.Control{}, fmt.Errorf("custom rule %q: %w", filepath.Join(rule.Dir, ruledir.RegoFileName), err)
	}

	return reporthandling.Control{
		ControlID:   customControlPrefix + rule.Name,
		Description: policy.Description,
		Remediation: policy.Remediation,
		Rules:       []reporthandling.PolicyRule{policy},
		BaseScore:   baseScore,
		PortalBase: armotypes.PortalBase{
			Name: customControlPrefix + rule.Name,
		},
	}, nil
}

func controlFromRegoFile(file string) (reporthandling.Control, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return reporthandling.Control{}, fmt.Errorf("read custom rule %q: %w", file, err)
	}

	baseScore, err := baseScoreFromRego(string(raw))
	if err != nil {
		return reporthandling.Control{}, fmt.Errorf("custom rule %q: %w", file, err)
	}

	name := strings.TrimSuffix(filepath.Base(file), ".rego")
	controlID := customControlPrefix + name
	description := fmt.Sprintf("User-authored custom rule from %s", file)

	rule := reporthandling.PolicyRule{
		Rule:         string(raw),
		Match:        matchAllKinds(),
		RuleLanguage: reporthandling.RegoLanguage,
		Description:  description,
		PortalBase: armotypes.PortalBase{
			Name: name,
		},
	}

	return reporthandling.Control{
		ControlID:   controlID,
		Description: description,
		Rules:       []reporthandling.PolicyRule{rule},
		BaseScore:   baseScore,
		PortalBase: armotypes.PortalBase{
			Name: controlID,
		},
	}, nil
}

// baseScoreFromRego reads the "# @baseScore <n>" annotation a rule may use to
// declare its own severity, and falls back to defaultCustomRuleBaseScore. A
// malformed or out-of-range value is an error rather than a fallback: silently
// defaulting would report a severity the rule did not ask for, and a typo in a
// CI-gating rule would go unnoticed.
func baseScoreFromRego(source string) (float32, error) {
	for _, line := range strings.Split(source, "\n") {
		comment, isComment := strings.CutPrefix(strings.TrimSpace(line), "#")
		if !isComment {
			continue
		}

		fields := strings.Fields(comment)
		if len(fields) == 0 || fields[0] != baseScoreAnnotation {
			continue
		}

		if len(fields) != 2 {
			return 0, fmt.Errorf("%s takes a single value, got %q", baseScoreAnnotation, strings.TrimSpace(comment))
		}
		// The range is tested positively so that NaN, which ParseFloat accepts,
		// is rejected rather than passing both bounds comparisons.
		baseScore, err := strconv.ParseFloat(fields[1], 32)
		if inRange := baseScore >= minCustomRuleBaseScore && baseScore <= maxCustomRuleBaseScore; err != nil || !inRange {
			return 0, fmt.Errorf("invalid %s %q: expected a number between %g and %g",
				baseScoreAnnotation, fields[1], minCustomRuleBaseScore, maxCustomRuleBaseScore)
		}
		return float32(baseScore), nil
	}

	return defaultCustomRuleBaseScore, nil
}

// matchAllKinds is the fallback for a rule that declares no selectors. Users
// can narrow it by writing a ResourceEnumerator snippet inside the rule.
func matchAllKinds() []reporthandling.RuleMatchObjects {
	return []reporthandling.RuleMatchObjects{{
		APIGroups:   []string{"*"},
		APIVersions: []string{"*"},
		Resources:   []string{"*"},
	}}
}

func customFramework(controls []reporthandling.Control) *reporthandling.Framework {
	return &reporthandling.Framework{
		PortalBase: armotypes.PortalBase{
			Name: "custom-rules",
		},
		Description: "User-authored custom rules",
		TypeTags:    []string{"custom"},
		Controls:    controls,
	}
}
