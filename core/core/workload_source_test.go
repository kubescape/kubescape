package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubescape/backend/pkg/versioncheck"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/cautils/getter"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/objectsenvelopes"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanContext_LocalWorkloadGitLabSource(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(t *testing.T, name, contents string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
		return path
	}
	const deployment = `apiVersion: apps/v1
kind: Deployment
metadata: {name: %s}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      hostPID: true
      containers:
        - name: web
          image: example.test/web:1
          securityContext:
            privileged: true
`
	writeFile(t, "input/manifests/other.yaml", fmt.Sprintf(deployment, "other"))
	selectedFile := writeFile(t, "input/manifests/selected.yaml", fmt.Sprintf(deployment, "selected"))

	const privileged = "spec.template.spec.containers[0].securityContext.privileged"
	const hostPID = "spec.template.spec.hostPID"
	newRule := func(name, condition, path, reportedObject string) reporthandling.PolicyRule {
		rule := reporthandling.PolicyRule{
			RuleLanguage: reporthandling.RegoLanguage,
			Match: []reporthandling.RuleMatchObjects{{
				APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"Deployment"},
			}},
			Rule: fmt.Sprintf(`package armo_builtins
import rego.v1

deny contains msg if {
	workload := input[_]
	%s
	msg := {"alertObject": {"k8sApiObjects": [%s]}, "reviewPaths": [%q]}
}
`, condition, reportedObject, path),
		}
		rule.Name = name
		return rule
	}
	// Policies can return the Kubernetes object with or without source metadata.
	kubernetesIDRule := newRule("privileged-containers", "workload.spec.template.spec.containers[_].securityContext.privileged", privileged, `object.remove(workload, ["sourcePath"])`)
	manifestIDRule := newRule("host-pid", "workload.spec.template.spec.hostPID", hostPID, "workload")
	enumeratedRule := manifestIDRule
	enumeratedRule.ResourceEnumerator = newRule("select-workload", "workload.spec.template.spec.hostPID", hostPID,
		`{"apiVersion": workload.apiVersion, "kind": workload.kind, "metadata": workload.metadata}`).Rule

	controlsInputs := writeFile(t, "controls-inputs.json", `{"probe":["value"]}`)
	exceptions := writeFile(t, "exceptions.json", "[]")
	attackTracks := writeFile(t, "attack-tracks.json", "[]")

	type finding struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Solution string `json:"solution"`
		Location struct {
			File string `json:"file"`
		} `json:"location"`
	}
	scan := func(t *testing.T, rules []reporthandling.PolicyRule, configure func(*cautils.ScanInfo)) []finding {
		t.Helper()
		control := reporthandling.Control{ControlID: "C-0057", BaseScore: 7, Rules: rules}
		control.Name = "Privileged container"
		framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
		framework.Name = "workload-source"
		policyJSON, err := json.Marshal(framework)
		require.NoError(t, err)
		policy := writeFile(t, "workload-source.json", string(policyJSON))
		policies := cautils.BuildPolicyIdentifiers([]string{framework.Name}, apisv1.KindFramework)
		scanInfo := &cautils.ScanInfo{
			InputPatterns:   []string{filepath.Join(dir, "input")},
			UseFrom:         []string{policy},
			ControlsInputs:  controlsInputs,
			UseExceptions:   exceptions,
			AttackTracks:    attackTracks,
			ScanObject:      &objectsenvelopes.ScanObject{Kind: "Deployment", Metadata: objectsenvelopes.ScanObjectMetadata{Name: "selected"}},
			ScanType:        cautils.ScanTypeWorkload,
			FrameworkScan:   true,
			NoClusterAccess: true,
			Local:           true,
			Format:          printer.GitLabSASTFormat,
			Output:          filepath.Join(t.TempDir(), "report.json"),
		}
		configure(scanInfo)
		scanInfo.Submit.SetBool(false)

		results, err := NewKubescape(t.Context()).ScanContext(t.Context(), scanInfo, policies)
		require.NoError(t, err)
		require.NoError(t, results.HandleResults(t.Context(), scanInfo))

		raw, err := os.ReadFile(scanInfo.Output)
		require.NoError(t, err)
		var report struct {
			Vulnerabilities []finding `json:"vulnerabilities"`
		}
		require.NoError(t, json.Unmarshal(raw, &report))
		return report.Vulnerabilities
	}

	tests := []struct {
		name      string
		rules     []reporthandling.PolicyRule
		evidence  []string
		streaming bool
	}{
		{name: "manifest ID", rules: []reporthandling.PolicyRule{manifestIDRule}, evidence: []string{hostPID}},
		{name: "Kubernetes ID", rules: []reporthandling.PolicyRule{kubernetesIDRule}, evidence: []string{privileged}},
		{name: "both IDs", rules: []reporthandling.PolicyRule{kubernetesIDRule, manifestIDRule}, evidence: []string{privileged, hostPID}},
		{name: "identity-only enumerator", rules: []reporthandling.PolicyRule{enumeratedRule}, evidence: []string{hostPID}},
		{name: "both IDs with streaming", rules: []reporthandling.PolicyRule{kubernetesIDRule, manifestIDRule}, evidence: []string{privileged, hostPID}, streaming: true},
	}

	var manifestFindingID string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scan(t, tt.rules, func(info *cautils.ScanInfo) {
				info.EnableStreaming = tt.streaming
			})
			require.Len(t, findings, 1)
			finding := findings[0]
			assert.Equal(t, "C-0057 - Privileged container", finding.Name)
			assert.Equal(t, "manifests/selected.yaml", finding.Location.File)
			for _, path := range tt.evidence {
				assert.Contains(t, finding.Solution, path+" (current: true)")
			}
			require.NotEmpty(t, finding.ID)
			if manifestFindingID == "" {
				manifestFindingID = finding.ID
			}
			assert.Equal(t, manifestFindingID, finding.ID)
		})
	}

	t.Run("cache does not share selection dependent verdicts", func(t *testing.T) {
		oldStore, oldBuild := getter.DefaultLocalStore, versioncheck.BuildNumber
		getter.DefaultLocalStore, versioncheck.BuildNumber = t.TempDir(), "v0.0.1"
		t.Cleanup(func() {
			getter.DefaultLocalStore, versioncheck.BuildNumber = oldStore, oldBuild
		})
		rules := []reporthandling.PolicyRule{kubernetesIDRule}
		selected := scan(t, rules, func(info *cautils.ScanInfo) {
			info.InputPatterns = []string{selectedFile}
			info.Incremental = true
		})
		require.Len(t, selected, 1)

		unselected := func(incremental bool) []finding {
			return scan(t, rules, func(info *cautils.ScanInfo) {
				info.InputPatterns = []string{selectedFile}
				info.ScanObject = nil
				info.ScanType = cautils.ScanTypeFramework
				info.Incremental = incremental
			})
		}
		assert.Equal(t, unselected(false), unselected(true), "a selected scan must not warm the cache with a selection dependent verdict")
	})
}
