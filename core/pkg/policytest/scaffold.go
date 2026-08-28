package policytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kubescape/kubescape/v4/core/pkg/ruledir"
)

const (
	flaggedCaseName = "flagged"
	cleanCaseName   = "clean"
	dirPerm         = 0o755
	filePerm        = 0o644
)

var ruleNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ScaffoldOptions configures the rule directory Scaffold writes.
type ScaffoldOptions struct {
	Kind        string
	Description string
	Remediation string
	Force       bool
}

type workloadKind struct {
	apiVersion     string
	regoContainers string
	failedPathBase string
	manifest       func(name, containers string) string
}

var workloadKinds = map[string]workloadKind{
	"Pod": {
		apiVersion:     "v1",
		regoContainers: "wl.spec.containers[i]",
		failedPathBase: "spec.",
		manifest: func(name, containers string) string {
			return fmt.Sprintf("apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: default\nspec:\n  containers:\n%s", name, indentBlock(containers, 4))
		},
	},
	"Deployment": {
		apiVersion:     "apps/v1",
		regoContainers: "wl.spec.template.spec.containers[i]",
		failedPathBase: "spec.template.spec.",
		manifest:       podTemplateManifest("apps/v1", "Deployment", ""),
	},
	"DaemonSet": {
		apiVersion:     "apps/v1",
		regoContainers: "wl.spec.template.spec.containers[i]",
		failedPathBase: "spec.template.spec.",
		manifest:       podTemplateManifest("apps/v1", "DaemonSet", ""),
	},
	"StatefulSet": {
		apiVersion:     "apps/v1",
		regoContainers: "wl.spec.template.spec.containers[i]",
		failedPathBase: "spec.template.spec.",
		manifest:       podTemplateManifest("apps/v1", "StatefulSet", "  serviceName: %s\n"),
	},
	"Job": {
		apiVersion:     "batch/v1",
		regoContainers: "wl.spec.template.spec.containers[i]",
		failedPathBase: "spec.template.spec.",
		manifest: func(name, containers string) string {
			return fmt.Sprintf("apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: %s\n  namespace: default\nspec:\n  template:\n    spec:\n      restartPolicy: Never\n      containers:\n%s", name, indentBlock(containers, 8))
		},
	},
	"CronJob": {
		apiVersion:     "batch/v1",
		regoContainers: "wl.spec.jobTemplate.spec.template.spec.containers[i]",
		failedPathBase: "spec.jobTemplate.spec.template.spec.",
		manifest: func(name, containers string) string {
			return fmt.Sprintf("apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: %s\n  namespace: default\nspec:\n  schedule: \"0 * * * *\"\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n          containers:\n%s", name, indentBlock(containers, 12))
		},
	},
}

func podTemplateManifest(apiVersion, kind, extraSpec string) func(name, containers string) string {
	return func(name, containers string) string {
		extra := ""
		if extraSpec != "" {
			extra = fmt.Sprintf(extraSpec, name)
		}
		return fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n  namespace: default\nspec:\n%s  selector:\n    matchLabels:\n      app: %s\n  template:\n    metadata:\n      labels:\n        app: %s\n    spec:\n      containers:\n%s",
			apiVersion, kind, name, extra, name, name, indentBlock(containers, 8))
	}
}

// SupportedKinds returns the workload kinds Scaffold can target.
func SupportedKinds() []string {
	kinds := make([]string, 0, len(workloadKinds))
	for kind := range workloadKinds {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// Scaffold writes a rule directory at dir holding raw.rego, rule.metadata.json
// and two test cases, then records each case's evaluator output in its
// expected.json so the rule passes RunRule as generated. A case that cannot be
// evaluated - one already in the directory with a malformed input, say - does
// not stop the rest from being recorded: the returned paths are the files
// written, sorted, alongside the joined errors for the cases that failed.
func Scaffold(ctx context.Context, dir string, opts ScaffoldOptions) ([]string, error) {
	name := filepath.Base(filepath.Clean(dir))
	if !ruleNamePattern.MatchString(name) {
		return nil, fmt.Errorf("rule name %q must be lowercase alphanumeric characters or '-', and start and end with an alphanumeric character", name)
	}

	kind := opts.Kind
	if kind == "" {
		kind = "Deployment"
	}
	template, ok := workloadKinds[kind]
	if !ok {
		return nil, fmt.Errorf("unsupported kind %q, supported: %s", kind, strings.Join(SupportedKinds(), ", "))
	}

	if !opts.Force && ruledir.Is(dir) {
		return nil, fmt.Errorf("%q already holds a rule, use --force to overwrite", dir)
	}

	description := opts.Description
	if description == "" {
		description = fmt.Sprintf("fails when a %s runs a container with securityContext.privileged set to true", kind)
	}
	remediation := opts.Remediation
	if remediation == "" {
		remediation = "Remove securityContext.privileged from the container, or set it to false."
	}

	metadata, err := marshalMetadata(name, kind, description, remediation)
	if err != nil {
		return nil, err
	}

	files := map[string]string{
		filepath.Join(dir, ruledir.RegoFileName):                              regoSource(kind, template),
		filepath.Join(dir, ruledir.MetadataFileName):                          metadata,
		filepath.Join(dir, "test", flaggedCaseName, "input", "resource.yaml"): template.manifest(name, containersBlock(true)),
		filepath.Join(dir, "test", cleanCaseName, "input", "resource.yaml"):   template.manifest(name, containersBlock(false)),
	}

	written := make([]string, 0, len(files))
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
			return nil, fmt.Errorf("create %q: %w", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), filePerm); err != nil {
			return nil, fmt.Errorf("write %q: %w", path, err)
		}
		written = append(written, path)
	}

	rules, err := DiscoverPath(dir)
	if err != nil {
		return nil, fmt.Errorf("discover scaffolded rule: %w", err)
	}
	if len(rules) != 1 {
		return nil, fmt.Errorf("expected one rule directory at %q, found %d", dir, len(rules))
	}

	var errs []error
	for _, c := range rules[0].Cases {
		responses, err := EvaluateCase(ctx, rules[0], c)
		if err != nil {
			errs = append(errs, fmt.Errorf("evaluate case %q: %w", c.Name, err))
			continue
		}
		changed, err := WriteExpected(c, responses)
		if err != nil {
			errs = append(errs, fmt.Errorf("case %q: %w", c.Name, err))
			continue
		}
		if changed {
			written = append(written, filepath.Join(c.Dir, expectedFileName))
		}
	}

	sort.Strings(written)
	return written, errors.Join(errs...)
}

type ruleMetadata struct {
	Name             string              `json:"name"`
	Attributes       map[string]any      `json:"attributes"`
	RuleLanguage     string              `json:"ruleLanguage"`
	Match            []ruleMetadataMatch `json:"match"`
	RuleDependencies []any               `json:"ruleDependencies"`
	Description      string              `json:"description"`
	Remediation      string              `json:"remediation"`
	RuleQuery        string              `json:"ruleQuery"`
}

type ruleMetadataMatch struct {
	APIGroups   []string `json:"apiGroups"`
	APIVersions []string `json:"apiVersions"`
	Resources   []string `json:"resources"`
}

func marshalMetadata(name, kind, description, remediation string) (string, error) {
	metadata := ruleMetadata{
		Name:         name,
		Attributes:   map[string]any{},
		RuleLanguage: "Rego",
		Match: []ruleMetadataMatch{{
			APIGroups:   []string{"*"},
			APIVersions: []string{"*"},
			Resources:   []string{kind},
		}},
		RuleDependencies: []any{},
		Description:      description,
		Remediation:      remediation,
		RuleQuery:        "armo_builtins",
	}

	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode %s: %w", ruledir.MetadataFileName, err)
	}
	return string(encoded) + "\n", nil
}

func regoSource(kind string, template workloadKind) string {
	const source = `package armo_builtins

import rego.v1

deny contains msga if {
	wl := input[_]
	wl.kind == "__KIND__"
	container := __CONTAINERS__
	container.securityContext.privileged == true

	path := sprintf("__PATH_BASE__containers[%d].securityContext.privileged", [i])

	msga := {
		"alertMessage": sprintf("container %v in __KIND__ %v runs as privileged", [container.name, wl.metadata.name]),
		"packagename": "armo_builtins",
		"alertScore": 7,
		"failedPaths": [path],
		"fixPaths": [],
		"alertObject": {"k8sApiObjects": [wl]},
	}
}
`

	return strings.NewReplacer(
		"__KIND__", kind,
		"__CONTAINERS__", template.regoContainers,
		"__PATH_BASE__", template.failedPathBase,
	).Replace(source)
}

func containersBlock(privileged bool) string {
	block := "- name: app\n  image: nginx:1.25\n"
	if privileged {
		block += "  securityContext:\n    privileged: true\n"
	}
	return block
}

func indentBlock(block string, spaces int) string {
	pad := strings.Repeat(" ", spaces)
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = pad + line
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
