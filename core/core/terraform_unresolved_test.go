package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	apisv1 "github.com/kubescape/opa-utils/httpserver/apis/v1"
	"github.com/kubescape/opa-utils/reporthandling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Regression test for #5832: a Terraform resource that uses a value the scan
// can't resolve used to make the whole configuration unscanned, so a
// privileged pod next to it was missing from the report with the scan still
// exiting 0.
func TestScanContext_TerraformResourceWithUnresolvedValueIsSkippedAlone(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, contents string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
		return path
	}
	writeFile("input/infra/main.tf", `
resource "kubernetes_namespace_v1" "apps" {
  metadata { name = "apps" }
}

resource "kubernetes_pod_v1" "plain" {
  metadata {
    name      = "plain"
    namespace = "default"
  }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
      security_context { privileged = true }
    }
  }
}

resource "kubernetes_pod_v1" "web" {
  metadata {
    name      = "web"
    namespace = kubernetes_namespace_v1.apps.metadata[0].name
  }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
      security_context { privileged = true }
    }
  }
}
`)
	writeFile("input/k8s/cm.yaml", "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cm, namespace: default}\n")

	rule := reporthandling.PolicyRule{
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}},
		Rule: `package armo_builtins
import rego.v1

deny contains msg if {
	pod := input[_]
	pod.spec.containers[_].securityContext.privileged
	msg := {"alertObject": {"k8sApiObjects": [pod]}, "reviewPaths": ["spec.containers[0].securityContext.privileged"]}
}
`,
	}
	rule.Name = "privileged-containers"
	control := reporthandling.Control{ControlID: "C-0057", BaseScore: 7, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "Privileged container"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "terraform-unresolved"
	policyJSON, err := json.Marshal(framework)
	require.NoError(t, err)

	scanInfo := &cautils.ScanInfo{
		InputPatterns:   []string{filepath.Join(dir, "input")},
		UseFrom:         []string{writeFile("terraform-unresolved.json", string(policyJSON))},
		ControlsInputs:  writeFile("controls-inputs.json", `{"probe":["value"]}`),
		UseExceptions:   writeFile("exceptions.json", "[]"),
		AttackTracks:    writeFile("attack-tracks.json", "[]"),
		ScanType:        cautils.ScanTypeFramework,
		FrameworkScan:   true,
		NoClusterAccess: true,
		Local:           true,
		Format:          printer.JsonFormat,
		Output:          filepath.Join(t.TempDir(), "report.json"),
	}
	scanInfo.Submit.SetBool(false)
	policies := cautils.BuildPolicyIdentifiers([]string{framework.Name}, apisv1.KindFramework)

	results, err := NewKubescape(t.Context()).ScanContext(t.Context(), scanInfo, policies)
	require.NoError(t, err, "valid Terraform must not fail the scan")
	require.NoError(t, results.HandleResults(t.Context(), scanInfo))

	raw, err := os.ReadFile(scanInfo.Output)
	require.NoError(t, err)
	var report struct {
		Results []struct {
			ResourceID string `json:"resourceID"`
			Controls   []struct {
				ControlID string `json:"controlID"`
				Status    struct {
					Status string `json:"status"`
				} `json:"status"`
			} `json:"controls"`
		} `json:"results"`
		ScanCoverage struct {
			SkippedManifests []struct {
				Path      string   `json:"path"`
				Reason    string   `json:"reason"`
				Resources []string `json:"resources"`
			} `json:"skippedManifests"`
		} `json:"scanCoverage"`
	}
	require.NoError(t, json.Unmarshal(raw, &report))

	// The pod that uses no unresolved value is scanned and fails C-0057.
	statuses := map[string]string{}
	for _, result := range report.Results {
		for _, control := range result.Controls {
			if control.ControlID == "C-0057" {
				statuses[result.ResourceID[strings.LastIndex(result.ResourceID, "/")+1:]] = control.Status.Status
			}
		}
	}
	assert.Equal(t, "failed", statuses["plain"], "the unrelated privileged pod must still be reported")
	assert.NotContains(t, statuses, "web", "a resource with an unresolved namespace is not scanned with it missing")

	// The resource that was left out is reported, so a scan that covered less
	// than the configuration says so.
	require.Len(t, report.ScanCoverage.SkippedManifests, 1)
	skipped := report.ScanCoverage.SkippedManifests[0]
	assert.Equal(t, filepath.Join(dir, "input", "infra"), skipped.Path)
	assert.Equal(t, []string{"kubernetes_pod_v1.web"}, skipped.Resources)
	assert.NotContains(t, skipped.Reason, "web", "the reason carries no resource labels, which --hide can't anonymize")
}

// Same setup as TestScanContext_TerraformResourceWithUnresolvedValueIsSkippedAlone,
// but the resources that can't be resolved are kubernetes_manifest blocks: one
// takes its namespace from another resource, one uses yamldecode.
func TestScanContext_KubernetesManifestWithUnresolvedValueIsReported(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name, contents string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
		return path
	}
	writeFile("input/infra/main.tf", `
resource "kubernetes_namespace_v1" "apps" {
  metadata { name = "apps" }
}

resource "kubernetes_pod_v1" "plain" {
  metadata {
    name      = "plain"
    namespace = "default"
  }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
      security_context { privileged = true }
    }
  }
}

resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web", namespace = kubernetes_namespace_v1.apps.metadata[0].name }
    spec = { containers = [{ name = "c", image = "nginx:1.27", securityContext = { privileged = true } }] }
  }
}

resource "kubernetes_manifest" "decoded" {
  manifest = yamldecode(<<-YAML
    apiVersion: v1
    kind: Pod
    metadata:
      name: decoded
      namespace: default
    spec:
      containers:
      - name: c
        image: nginx:1.27
        securityContext:
          privileged: true
    YAML
  )
}
`)

	rule := reporthandling.PolicyRule{
		RuleLanguage: reporthandling.RegoLanguage,
		Match: []reporthandling.RuleMatchObjects{{
			APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"Pod"},
		}},
		Rule: `package armo_builtins
import rego.v1

deny contains msg if {
	pod := input[_]
	pod.spec.containers[_].securityContext.privileged
	msg := {"alertObject": {"k8sApiObjects": [pod]}, "reviewPaths": ["spec.containers[0].securityContext.privileged"]}
}
`,
	}
	rule.Name = "privileged-containers"
	control := reporthandling.Control{ControlID: "C-0057", BaseScore: 7, Rules: []reporthandling.PolicyRule{rule}}
	control.Name = "Privileged container"
	framework := reporthandling.Framework{Controls: []reporthandling.Control{control}}
	framework.Name = "terraform-manifest-unresolved"
	policyJSON, err := json.Marshal(framework)
	require.NoError(t, err)

	scanInfo := &cautils.ScanInfo{
		InputPatterns:   []string{filepath.Join(dir, "input")},
		UseFrom:         []string{writeFile("terraform-manifest-unresolved.json", string(policyJSON))},
		ControlsInputs:  writeFile("controls-inputs.json", `{"probe":["value"]}`),
		UseExceptions:   writeFile("exceptions.json", "[]"),
		AttackTracks:    writeFile("attack-tracks.json", "[]"),
		ScanType:        cautils.ScanTypeFramework,
		FrameworkScan:   true,
		NoClusterAccess: true,
		Local:           true,
		Format:          printer.JsonFormat,
		Output:          filepath.Join(t.TempDir(), "report.json"),
	}
	scanInfo.Submit.SetBool(false)
	policies := cautils.BuildPolicyIdentifiers([]string{framework.Name}, apisv1.KindFramework)

	results, err := NewKubescape(t.Context()).ScanContext(t.Context(), scanInfo, policies)
	require.NoError(t, err, "valid Terraform must not fail the scan")
	require.NoError(t, results.HandleResults(t.Context(), scanInfo))

	raw, err := os.ReadFile(scanInfo.Output)
	require.NoError(t, err)
	var report struct {
		Results []struct {
			ResourceID string `json:"resourceID"`
			Controls   []struct {
				ControlID string `json:"controlID"`
				Status    struct {
					Status string `json:"status"`
				} `json:"status"`
			} `json:"controls"`
		} `json:"results"`
		ScanCoverage struct {
			SkippedManifests []struct {
				Path      string   `json:"path"`
				Reason    string   `json:"reason"`
				Resources []string `json:"resources"`
			} `json:"skippedManifests"`
		} `json:"scanCoverage"`
	}
	require.NoError(t, json.Unmarshal(raw, &report))

	statuses := map[string]string{}
	for _, result := range report.Results {
		for _, control := range result.Controls {
			if control.ControlID == "C-0057" {
				statuses[result.ResourceID[strings.LastIndex(result.ResourceID, "/")+1:]] = control.Status.Status
			}
		}
	}
	assert.Equal(t, "failed", statuses["plain"], "the resolvable privileged pod must still be reported")
	assert.NotContains(t, statuses, "web")
	assert.NotContains(t, statuses, "decoded")

	// The two kubernetes_manifest blocks that were left out must be reported,
	// like a typed resource with an unresolved value is.
	require.Len(t, report.ScanCoverage.SkippedManifests, 1, "left-out kubernetes_manifest blocks are not reported")
	skipped := report.ScanCoverage.SkippedManifests[0]
	assert.Equal(t, filepath.Join(dir, "input", "infra"), skipped.Path)
	assert.ElementsMatch(t, []string{"kubernetes_manifest.web", "kubernetes_manifest.decoded"}, skipped.Resources)
	for _, label := range []string{"web", "decoded"} {
		assert.NotContains(t, skipped.Reason, label, "the reason carries no resource labels, which --hide can't anonymize")
	}
}
