package getter

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling"
)

// LoadCustomRules discovers *.rego files under path and returns a synthetic
// framework that wraps each file as a control. An empty or missing path is not
// an error and returns a nil framework.
func LoadCustomRules(path string) (*reporthandling.Framework, error) {
	if path == "" {
		return nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("custom rules path %q: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("read custom rules directory %q: %w", path, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
				continue
			}
			files = append(files, filepath.Join(path, e.Name()))
		}
		// Readdir is unordered; sort for stable control IDs and reports.
		sort.Strings(files)
	} else if strings.HasSuffix(path, ".rego") {
		files = []string{path}
	}

	if len(files) == 0 {
		return nil, nil
	}

	controls := make([]reporthandling.Control, 0, len(files))
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".rego")
		controlID := "custom-" + name

		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read custom rule %q: %w", file, err)
		}

		rule := reporthandling.PolicyRule{
			Rule: string(raw),
			// Match all Kubernetes object kinds by default. Users can narrow
			// selection by writing a ResourceEnumerator rego snippet inside the rule.
			Match: []reporthandling.RuleMatchObjects{{
				APIGroups:   []string{"*"},
				APIVersions: []string{"*"},
				Resources:   []string{"*"},
			}},
			RuleLanguage: reporthandling.RegoLanguage,
			Description:  fmt.Sprintf("User-authored custom rule from %s", file),
			PortalBase: armotypes.PortalBase{
				Name: name,
			},
		}

		control := reporthandling.Control{
			ControlID:   controlID,
			Description: rule.Description,
			Rules:       []reporthandling.PolicyRule{rule},
			PortalBase: armotypes.PortalBase{
				Name: controlID,
			},
		}
		controls = append(controls, control)
	}

	return &reporthandling.Framework{
		PortalBase: armotypes.PortalBase{
			Name: "custom-rules",
		},
		Description: "User-authored custom rules",
		TypeTags:    []string{"custom"},
		Controls:    controls,
	}, nil
}
