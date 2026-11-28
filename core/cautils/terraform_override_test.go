package cautils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

// writeTerraformOverrideFiles writes each named file into dir.
func writeTerraformOverrideFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
}

// terraformOverrideWorkloads returns every workload, whichever file it is
// keyed by, after checking that override files have none of their own.
func terraformOverrideWorkloads(t *testing.T, workloads map[string][]workloadinterface.IMetadata) []workloadinterface.IMetadata {
	t.Helper()
	var all []workloadinterface.IMetadata
	for src, wls := range workloads {
		assert.False(t, isTerraformOverrideFile(src), "override file %s must not produce workloads of its own", src)
		all = append(all, wls...)
	}
	return all
}

func podSpec(t *testing.T, w workloadinterface.IMetadata) map[string]interface{} {
	t.Helper()
	spec, ok := w.GetObject()["spec"].(map[string]interface{})
	require.True(t, ok, "spec must be an object")
	return spec
}

const overrideBaseManifestPod = `
variable "host_network" {
  type    = bool
  default = true
}

resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web", namespace = "default" }
    spec = {
      hostNetwork = var.host_network
      containers  = [{ name = "web", image = "nginx:1.25" }]
    }
  }
}
`

func TestIsTerraformOverrideFile(t *testing.T) {
	tests := map[string]bool{
		"override.tf":                     true,
		"web_override.tf":                 true,
		"_override.tf":                    true,
		"/a/b/dev_override.tf":            true,
		"draft_override.tf":               true,
		"api_override.tf":                 true,
		".override.tf":                    false, // hidden files are ignored
		".draft_override.tf":              false,
		"/a/b/.dev_override.tf":           false,
		".draft_override.tf.json":         false,
		"main.tf":                         false,
		"overrides.tf":                    false,
		"override_main.tf":                false,
		"web-override.tf":                 false,
		"weboverride.tf":                  false,
		"override.tf.json":                false, // .tf.json is not read
		"web_override.tf.json":            false,
		"override.tfvars":                 false,
		"override.tf.bak":                 false,
		filepath.Join("override", "x.tf"): false,
	}
	for name, want := range tests {
		assert.Equal(t, want, isTerraformOverrideFile(name), name)
	}
}

// The reproduction from issue #5444: the override is merged into main.tf
// instead of producing a second workload with the same identity.
func TestTerraformDirectory_GetWorkloads_OverrideFixture(t *testing.T) {
	dir := "testdata/terraform_override"
	td := NewTerraformDirectory(dir)
	workloads, errs := td.GetWorkloads(dir)
	require.Empty(t, errs)

	main := filepath.Join(dir, "main.tf")
	require.Len(t, workloads, 1, "only main.tf has workloads")
	require.Len(t, workloads[main], 2)

	byName := map[string]workloadinterface.IMetadata{}
	for _, w := range workloads[main] {
		byName[w.GetName()] = w
	}

	web := podSpec(t, byName["web"])
	assert.Equal(t, false, web["hostNetwork"])

	// The typed resource's spec block is replaced as a whole, its metadata
	// block kept from main.tf.
	api := byName["api"]
	require.NotNil(t, api)
	assert.Equal(t, "default", api.GetNamespace())
	apiSpec := podSpec(t, api)
	assert.Equal(t, false, apiSpec["hostNetwork"])
	assert.NotContains(t, apiSpec, "hostPID", "nested blocks are replaced, not merged")
	containers := apiSpec["containers"].([]interface{})
	require.Len(t, containers, 1)
	assert.Equal(t, "nginx:1.27", containers[0].(map[string]interface{})["image"])

	// Findings still point at the resource blocks in main.tf.
	var lines []int
	for i := range workloads[main] {
		loc, ok := td.SourceLocations()[terraformWorkloadPath(main, i)]
		require.True(t, ok)
		lines = append(lines, loc.Line)
	}
	assert.ElementsMatch(t, []int{1, 19}, lines)
}

// Override files are applied after primary files whatever their names, so an
// override that sorts before the primary file still wins.
func TestTerraformDirectory_GetWorkloads_OverrideSortsBeforePrimary(t *testing.T) {
	dir := t.TempDir()
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"z_main.tf": overrideBaseManifestPod,
		"a_override.tf": `
resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web", namespace = "default" }
    spec       = { hostNetwork = false, containers = [{ name = "web", image = "nginx:1.25" }] }
  }
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	all := terraformOverrideWorkloads(t, workloads)
	require.Len(t, all, 1)
	assert.Equal(t, false, podSpec(t, all[0])["hostNetwork"])
	assert.Contains(t, workloads, filepath.Join(dir, "z_main.tf"))
}

// An override argument replaces only the argument of the same name; the
// base resource's other arguments, including count, are kept.
func TestTerraformDirectory_GetWorkloads_OverrideKeepsOtherArguments(t *testing.T) {
	dir := t.TempDir()
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_manifest" "web" {
  count = 2
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web-${count.index}", namespace = "default" }
    spec       = { hostNetwork = true, containers = [{ name = "web", image = "nginx:1.25" }] }
  }
}
`,
		"override.tf": `
resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web-${count.index}", namespace = "default" }
    spec       = { hostNetwork = false, containers = [{ name = "web", image = "nginx:1.25" }] }
  }
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	all := terraformOverrideWorkloads(t, workloads)
	require.Len(t, all, 2)
	for _, w := range all {
		assert.Equal(t, false, podSpec(t, w)["hostNetwork"], w.GetName())
	}
}

// A typed resource override that sets only part of a nested block replaces
// that whole block type, and leaves other block types alone.
func TestTerraformDirectory_GetWorkloads_TypedResourcePartialBlockOverride(t *testing.T) {
	dir := t.TempDir()
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_deployment_v1" "app" {
  metadata {
    name      = "app"
    namespace = "prod"
  }
  spec {
    replicas = 3
    selector {
      match_labels = { app = "app" }
    }
    template {
      metadata {
        labels = { app = "app" }
      }
      spec {
        container {
          name  = "app"
          image = "nginx:1.25"
        }
      }
    }
  }
}
`,
		"app_override.tf": `
resource "kubernetes_deployment_v1" "app" {
  metadata {
    name   = "app"
    labels = { team = "web" }
  }
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	all := terraformOverrideWorkloads(t, workloads)
	require.Len(t, all, 1)
	w := all[0]
	assert.Equal(t, "Deployment", w.GetKind())
	assert.Equal(t, "app", w.GetName())
	metadata := w.GetObject()["metadata"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"team": "web"}, metadata["labels"])
	// The base metadata block, and with it namespace = "prod", was replaced.
	assert.NotEqual(t, "prod", w.GetNamespace())
	// The spec block was not overridden.
	spec := podSpec(t, w)
	assert.Equal(t, json.Number("3"), spec["replicas"])
	assert.NotNil(t, spec["template"])
}

func TestTerraformDirectory_GetWorkloads_OverrideVariableDefault(t *testing.T) {
	t.Run("later override file wins", func(t *testing.T) {
		dir := t.TempDir()
		writeTerraformOverrideFiles(t, dir, map[string]string{
			"main.tf": overrideBaseManifestPod,
			// override.tf sorts after dev_override.tf, so its default is in effect.
			"dev_override.tf": `
variable "host_network" {
  default = true
}
`,
			"override.tf": `
variable "host_network" {
  default = false
}
`,
		})
		workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
		require.Empty(t, errs)
		all := terraformOverrideWorkloads(t, workloads)
		require.Len(t, all, 1)
		assert.Equal(t, false, podSpec(t, all[0])["hostNetwork"])
	})

	t.Run("keeps the base type constraint", func(t *testing.T) {
		dir := t.TempDir()
		writeTerraformOverrideFiles(t, dir, map[string]string{
			"main.tf": overrideBaseManifestPod,
			// "false" is converted by the base type = bool.
			"dev_override.tf": `
variable "host_network" {
  default = "false"
}
`,
		})
		workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
		require.Empty(t, errs)
		all := terraformOverrideWorkloads(t, workloads)
		require.Len(t, all, 1)
		assert.Equal(t, false, podSpec(t, all[0])["hostNetwork"])
	})

	t.Run("overridden type converts the base default", func(t *testing.T) {
		dir := t.TempDir()
		writeTerraformOverrideFiles(t, dir, map[string]string{
			"main.tf": `
variable "replicas" {
  default = "2"
}

resource "kubernetes_manifest" "app" {
  manifest = {
    apiVersion = "apps/v1"
    kind       = "Deployment"
    metadata   = { name = "app", namespace = "default" }
    spec       = { replicas = var.replicas }
  }
}
`,
			"override.tf": `
variable "replicas" {
  type = number
}
`,
		})
		workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
		require.Empty(t, errs)
		all := terraformOverrideWorkloads(t, workloads)
		require.Len(t, all, 1)
		assert.Equal(t, json.Number("2"), podSpec(t, all[0])["replicas"])
	})

	t.Run("tfvars still take precedence over an overridden default", func(t *testing.T) {
		dir := t.TempDir()
		writeTerraformOverrideFiles(t, dir, map[string]string{
			"main.tf": overrideBaseManifestPod,
			"override.tf": `
variable "host_network" {
  default = false
}
`,
			"terraform.tfvars": `host_network = true`,
		})
		workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
		require.Empty(t, errs)
		all := terraformOverrideWorkloads(t, workloads)
		require.Len(t, all, 1)
		assert.Equal(t, true, podSpec(t, all[0])["hostNetwork"])
	})
}

// Terraform's Variable.merge replaces a variable's type constraint but keeps
// the optional attribute defaults of the primary declaration; an override's
// own optional attribute defaults only apply to a default it sets itself.
func TestTerraformDirectory_GetWorkloads_OverrideVariableTypeDefaults(t *testing.T) {
	const manifest = `
resource "kubernetes_manifest" "pod" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "pod", namespace = "default" }
    spec       = { securityContext = var.sc }
  }
}
`
	tests := []struct {
		name     string
		files    map[string]string
		expected interface{}
	}{
		{
			name: "primary optional default is kept",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type    = object({ privileged = optional(bool, false) })
  default = {}
}
` + manifest,
				"override.tf": `
variable "sc" {
  type = object({ privileged = optional(bool, true) })
}
`,
			},
			expected: false,
		},
		{
			// The reverse direction: Terraform decodes the primary default with
			// the primary type's optional defaults, and a type-only override
			// does not decode it again with its own.
			name: "primary optional default is kept when the override's is false",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type    = object({ privileged = optional(bool, true) })
  default = {}
}
` + manifest,
				"override.tf": `
variable "sc" {
  type = object({ privileged = optional(bool, false) })
}
`,
			},
			expected: true,
		},
		{
			name: "overriding type's optional default is not applied to the primary default",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type    = object({ privileged = optional(bool) })
  default = {}
}
` + manifest,
				"override.tf": `
variable "sc" {
  type = object({ privileged = optional(bool, true) })
}
`,
			},
			expected: nil,
		},
		{
			name: "overriding type's optional default applies to its own default",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type    = object({ privileged = optional(bool) })
  default = { privileged = false }
}
` + manifest,
				"override.tf": `
variable "sc" {
  type    = object({ privileged = optional(bool, true) })
  default = {}
}
`,
			},
			expected: true,
		},
		{
			// Each override file is merged in turn: a_override.tf changes the
			// type, b_override.tf then sets a default that is converted to it,
			// and only the primary optional defaults are applied to the result.
			name: "type and default overridden in sequence",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type    = object({ privileged = optional(bool, false), host = optional(bool) })
  default = { host = true }
}
` + manifest,
				"a_override.tf": `
variable "sc" {
  type = object({ privileged = optional(bool, true), host = optional(bool), extra = optional(string, "x") })
}
`,
				"b_override.tf": `
variable "sc" {
  default = {}
}
`,
			},
			expected: false,
		},
		{
			name: "tfvars values get the primary optional default",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type = object({ privileged = optional(bool, false) })
}
` + manifest,
				"override.tf": `
variable "sc" {
  type = object({ privileged = optional(bool, true) })
}
`,
				"terraform.tfvars": `sc = {}`,
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, tt.files)
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.Empty(t, errs)
			all := terraformOverrideWorkloads(t, workloads)
			require.Len(t, all, 1)
			securityContext, ok := podSpec(t, all[0])["securityContext"].(map[string]interface{})
			require.True(t, ok, "securityContext must be an object")
			require.Contains(t, securityContext, "privileged")
			assert.Equal(t, tt.expected, securityContext["privileged"])
		})
	}
}

// A variable override Terraform rejects never yields a value: the reference
// stays unresolved, so the resource is skipped instead of being scanned with
// a value Terraform would not apply.
func TestTerraformDirectory_GetWorkloads_RejectedVariableOverride(t *testing.T) {
	const manifest = `
resource "kubernetes_manifest" "web" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web", namespace = "default" }
    spec       = { hostNetwork = var.host_network }
  }
}
`
	tests := []struct {
		name  string
		files map[string]string
		// expected is the hostNetwork scanned, or nil when the resource
		// must be skipped.
		expected interface{}
	}{
		{
			name: "invalid type does not turn a variable file value into a string",
			files: map[string]string{
				"main.tf":          "variable \"host_network\" {\n  type = bool\n}\n" + manifest,
				"override.tf":      "variable \"host_network\" {\n  type = boool\n}\n",
				"terraform.tfvars": `host_network = "true"`,
			},
		},
		{
			name: "invalid type does not replace the default",
			files: map[string]string{
				"main.tf":     "variable \"host_network\" {\n  type    = bool\n  default = false\n}\n" + manifest,
				"override.tf": "variable \"host_network\" {\n  type    = list(boool)\n  default = \"true\"\n}\n",
			},
		},
		{
			name: "invalid default does not fall back to the primary default",
			files: map[string]string{
				"main.tf":     "variable \"host_network\" {\n  type    = bool\n  default = false\n}\n" + manifest,
				"override.tf": "variable \"host_network\" {\n  default = \"not a bool\"\n}\n",
			},
		},
		{
			name: "null default of a non-nullable variable",
			files: map[string]string{
				"main.tf":     "variable \"host_network\" {\n  type     = bool\n  default  = false\n  nullable = false\n}\n" + manifest,
				"override.tf": "variable \"host_network\" {\n  default = null\n}\n",
			},
		},
		{
			name: "non-nullable override of a null default",
			files: map[string]string{
				"main.tf":     "variable \"host_network\" {\n  type    = bool\n  default = null\n}\n" + manifest,
				"override.tf": "variable \"host_network\" {\n  nullable = false\n}\n",
			},
		},
		{
			name: "rejected default can still be set by a variable file",
			files: map[string]string{
				"main.tf":          "variable \"host_network\" {\n  type     = bool\n  default  = false\n  nullable = false\n}\n" + manifest,
				"override.tf":      "variable \"host_network\" {\n  default = null\n}\n",
				"terraform.tfvars": `host_network = true`,
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, tt.files)
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			all := terraformOverrideWorkloads(t, workloads)
			if tt.expected == nil {
				resources, ok := onlyTerraformResourceErrors(errs)
				require.True(t, ok, "the skipped resource is reported on its own: %v", errs)
				assert.Equal(t, []string{"kubernetes_manifest.web"}, resources)
				assert.Empty(t, all)
				return
			}
			require.Empty(t, errs)
			require.Len(t, all, 1)
			assert.Equal(t, tt.expected, podSpec(t, all[0])["hostNetwork"])
		})
	}
}

// An expression merged from an override file that fails to evaluate is
// reported at its location in the override file.
func TestTerraformDirectory_GetWorkloads_OverrideEvaluationErrorLocation(t *testing.T) {
	dir := t.TempDir()
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_pod_v1" "web" {
  metadata {
    name = "web"
  }
  spec {
    container {
      name  = "web"
      image = "nginx:1.25"
    }
  }
}
`,
		"override.tf": `
resource "kubernetes_pod_v1" "web" {
  spec {
    container {
      name  = "web"
      image = 1 + "abc"
    }
  }
}
`,
	})

	_, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Len(t, errs, 1)
	var diags hcl.Diagnostics
	require.True(t, errors.As(errs[0], &diags), "the error wraps the HCL diagnostics")
	require.NotEmpty(t, diags)
	subject := diags[0].Subject
	require.NotNil(t, subject)
	assert.Equal(t, filepath.Join(dir, "override.tf"), subject.Filename)
	assert.Equal(t, hcl.Pos{Line: 6, Column: 19, Byte: subject.Start.Byte}, subject.Start)
	assert.Equal(t, 6, subject.End.Line)
	assert.Contains(t, errs[0].Error(), filepath.Join(dir, "override.tf")+":6,19-24")
}

func TestTerraformDirectory_GetWorkloads_OverrideLocals(t *testing.T) {
	dir := t.TempDir()
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"main.tf": `
locals {
  host_network = true
  image        = "nginx:1.25"
}

resource "kubernetes_pod_v1" "web" {
  metadata {
    name      = "web"
    namespace = "default"
  }
  spec {
    host_network = local.host_network
    host_pid     = local.host_pid
    container {
      name  = "web"
      image = local.image
    }
  }
}
`,
		"locals.tf": `
locals {
  host_pid = local.host_network
}
`,
		"dev_override.tf": `
locals {
  host_network = false
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	all := terraformOverrideWorkloads(t, workloads)
	require.Len(t, all, 1)
	spec := podSpec(t, all[0])
	assert.Equal(t, false, spec["hostNetwork"])
	// Locals referencing the overridden one see the override, and the other
	// locals of the overridden block are kept.
	assert.Equal(t, false, spec["hostPID"])
	containers := spec["containers"].([]interface{})
	assert.Equal(t, "nginx:1.25", containers[0].(map[string]interface{})["image"])
}

// An override with no primary definition is a Terraform configuration error.
// It is reported and skipped, never extracted as a workload of its own, while
// the matching overrides of the same file still apply.
func TestTerraformDirectory_GetWorkloads_UnmatchedOverrides(t *testing.T) {
	dir := t.TempDir()
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"main.tf": overrideBaseManifestPod + `
locals {
  image = "nginx:1.25"
}
`,
		"override.tf": `
variable "host_network" {
  default = false
}

variable "missing_variable" {
  default = "x"
}

locals {
  image         = "nginx:1.27"
  missing_local = "x"
}

resource "kubernetes_pod_v1" "extra" {
  metadata {
    name = "extra"
  }
  spec {
    host_network = true
    container {
      name  = "extra"
      image = "nginx:1.25"
    }
  }
}

resource "kubernetes_manifest" "web2" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "web2" }
    spec       = { hostNetwork = true }
  }
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Len(t, errs, 4)
	assert.True(t, onlyTerraformMissingOverrideTargets(errs), "unmatched overrides are told apart from other errors")
	var messages []string
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	joined := strings.Join(messages, "\n")
	overridePath := filepath.Join(dir, "override.tf")
	assert.Contains(t, joined, `there is no variable named "missing_variable"`)
	assert.Contains(t, joined, `there is no local value named "missing_local"`)
	assert.Contains(t, joined, `there is no kubernetes_pod_v1 resource named "extra"`)
	assert.Contains(t, joined, `there is no kubernetes_manifest resource named "web2"`)
	for _, msg := range messages {
		assert.Contains(t, msg, overridePath, "errors point at the override file")
	}

	all := terraformOverrideWorkloads(t, workloads)
	require.Len(t, all, 1, "unmatched override resources are skipped")
	assert.Equal(t, "web", all[0].GetName())
	assert.Equal(t, false, podSpec(t, all[0])["hostNetwork"], "matched overrides still apply")
}

// workloadNames returns the names of all workloads, whichever file they are
// keyed by.
func workloadNames(workloads map[string][]workloadinterface.IMetadata) []string {
	var names []string
	for _, wls := range workloads {
		for _, w := range wls {
			names = append(names, w.GetName())
		}
	}
	return names
}

// Unmatched overrides are still reported: a directly scanned directory
// returns the error, a nested one is logged and recorded as a skip. The
// unmatched block is all that is skipped, so the workloads the directory
// defines are kept in both cases.
func TestLoadResourcesFromTerraform_UnmatchedOverride(t *testing.T) {
	tests := []struct {
		name     string
		override string
		message  string
	}{
		{
			name:     "resource",
			override: `resource "kubernetes_manifest" "missing" {}`,
			message:  `there is no kubernetes_manifest resource named "missing"`,
		},
		{
			// The base declaration is in a .tf.json file, which is not read,
			// so the override matches nothing; the independent Pod in
			// main.tf must still be scanned.
			name:     "variable declared in a .tf.json file",
			override: "variable \"replicas\" {\n  default = 3\n}\n",
			message:  `there is no variable named "replicas"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := resolvedTempDir(t)
			nested := filepath.Join(root, "modules", "app")
			require.NoError(t, os.MkdirAll(nested, 0o700))
			writeTerraformOverrideFiles(t, nested, map[string]string{
				"main.tf":           overrideBaseManifestPod,
				"variables.tf.json": `{"variable": {"replicas": {"type": "number"}}}`,
				"override.tf":       tt.override,
			})

			// Nested directory.
			workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), root, nil, root)
			require.NoError(t, err)
			assert.Equal(t, []string{"web"}, workloadNames(workloads))
			require.Len(t, skips, 1)
			assert.Equal(t, nested, skips[0].Path)
			assert.Contains(t, skips[0].Reason, "override blocks could not be applied")

			// Explicitly scanned directory.
			workloads, _, err = LoadResourcesFromTerraformFilteredWithSkips(context.Background(), nested, nil, root)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.message)
			assert.Equal(t, []string{"web"}, workloadNames(workloads))

			// Explicitly scanned file.
			workloads, _, err = LoadResourcesFromTerraformFilteredWithSkips(context.Background(), filepath.Join(nested, "main.tf"), nil, root)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.message)
			assert.Equal(t, []string{"web"}, workloadNames(workloads))
		})
	}
}

// A directory with any other error alongside an unmatched override, apart from
// resources left out for unresolved values, keeps the existing policy: a
// nested one is skipped as a whole, a directly scanned one fails without its
// workloads.
func TestLoadResourcesFromTerraform_UnmatchedOverrideWithOtherErrors(t *testing.T) {
	root := resolvedTempDir(t)
	nested := filepath.Join(root, "modules", "app")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	writeTerraformOverrideFiles(t, nested, map[string]string{
		"main.tf":     overrideBaseManifestPod,
		"broken.tf":   "this is not valid HCL",
		"override.tf": `resource "kubernetes_manifest" "missing" {}`,
	})

	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), root, nil, root)
	require.NoError(t, err)
	assert.Empty(t, workloadNames(workloads))
	require.Len(t, skips, 1)
	assert.Equal(t, nested, skips[0].Path)
	assert.Equal(t, "failed to render Terraform configuration; see scan logs for details", skips[0].Reason)

	workloads, _, err = LoadResourcesFromTerraformFilteredWithSkips(context.Background(), nested, nil, root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `there is no kubernetes_manifest resource named "missing"`)
	assert.Contains(t, err.Error(), "broken.tf")
	assert.Empty(t, workloadNames(workloads))
}

// Resources left out for unresolved values next to an unmatched override don't
// drop the nested configuration: its other workloads are scanned, and both the
// override and the resources left out are reported.
func TestLoadResourcesFromTerraform_UnmatchedOverrideWithUnresolvedResources(t *testing.T) {
	tests := []struct {
		name       string
		unresolved string
		resource   string
	}{
		{
			name: "kubernetes_manifest",
			unresolved: `
resource "kubernetes_manifest" "ns_ref" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "ns-ref", namespace = kubernetes_namespace_v1.apps.metadata[0].name }
  }
}
`,
			resource: "kubernetes_manifest.ns_ref",
		},
		{
			name: "typed resource",
			unresolved: `
resource "kubernetes_pod_v1" "ns_ref" {
  metadata {
    name      = "ns-ref"
    namespace = kubernetes_namespace_v1.apps.metadata[0].name
  }
  spec {
    container {
      name  = "c"
      image = "nginx:1.27"
    }
  }
}
`,
			resource: "kubernetes_pod_v1.ns_ref",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := resolvedTempDir(t)
			nested := filepath.Join(root, "modules", "app")
			require.NoError(t, os.MkdirAll(nested, 0o700))
			writeTerraformOverrideFiles(t, nested, map[string]string{
				"main.tf":     overrideBaseManifestPod + "\nresource \"kubernetes_namespace_v1\" \"apps\" {\n  metadata { name = \"apps\" }\n}\n" + tt.unresolved,
				"override.tf": `resource "kubernetes_manifest" "missing" {}`,
			})

			workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), root, nil, root)
			require.NoError(t, err)
			assert.ElementsMatch(t, []string{"web", "apps"}, workloadNames(workloads))
			require.Len(t, skips, 2)
			assert.Equal(t, nested, skips[0].Path)
			assert.Contains(t, skips[0].Reason, "override blocks could not be applied")
			assert.Equal(t, nested, skips[1].Path)
			assert.Equal(t, []string{tt.resource}, skips[1].Resources)

			// A directly scanned directory still fails, as with an unmatched
			// override alone.
			_, _, err = LoadResourcesFromTerraformFilteredWithSkips(context.Background(), nested, nil, root)
			require.Error(t, err)
			assert.Contains(t, err.Error(), `there is no kubernetes_manifest resource named "missing"`)
		})
	}
}

func TestOnlyTerraformMissingOverrideTargets(t *testing.T) {
	missing := missingTerraformOverrideTarget("missing %s", "x")
	assert.Equal(t, "missing x", missing.Error())
	assert.False(t, onlyTerraformMissingOverrideTargets(nil))
	assert.True(t, onlyTerraformMissingOverrideTargets([]error{missing}))
	assert.True(t, onlyTerraformMissingOverrideTargets([]error{fmt.Errorf("wrapped: %w", missing)}))
	assert.False(t, onlyTerraformMissingOverrideTargets([]error{missing, errors.New("parse error")}))
}

// Several override files of one resource apply in file name order, whatever
// order the files were created in.
func TestTerraformDirectory_GetWorkloads_MultipleOverrideFilesDeterministic(t *testing.T) {
	overrideImage := func(image string) string {
		return `
resource "kubernetes_pod_v1" "web" {
  spec {
    container {
      name  = "web"
      image = "` + image + `"
    }
  }
}
`
	}
	dir := t.TempDir()
	// Created in reverse order of their names.
	for _, f := range []struct{ name, content string }{
		{"c_override.tf", overrideImage("nginx:c")},
		{"b_override.tf", overrideImage("nginx:b")},
		{"a_override.tf", overrideImage("nginx:a")},
		{"main.tf", `
resource "kubernetes_pod_v1" "web" {
  metadata {
    name      = "web"
    namespace = "default"
  }
  spec {
    container {
      name  = "web"
      image = "nginx:base"
    }
  }
}
`},
	} {
		writeTerraformOverrideFiles(t, dir, map[string]string{f.name: f.content})
	}

	for range 5 {
		workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
		require.Empty(t, errs)
		all := terraformOverrideWorkloads(t, workloads)
		require.Len(t, all, 1)
		containers := podSpec(t, all[0])["containers"].([]interface{})
		require.Len(t, containers, 1)
		assert.Equal(t, "nginx:c", containers[0].(map[string]interface{})["image"])
	}
}

// A merged resource counts the source of its override blocks towards the
// count and for_each expansion limit, so an override cannot multiply a large
// body by a count that the small base block alone would allow.
func TestTerraformDirectory_GetWorkloads_OverrideCountsTowardsExpansionLimit(t *testing.T) {
	dir := t.TempDir()
	padding := strings.Repeat("x", 20000)
	writeTerraformOverrideFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_pod_v1" "big" {
  metadata {
    name = "big"
  }
}
`,
		"override.tf": `
resource "kubernetes_pod_v1" "big" {
  count = 1000
  metadata {
    name        = "big"
    annotations = { pad = "` + padding + `" }
  }
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "count or for_each expansion exceeds the size limit")
	assert.Empty(t, terraformOverrideWorkloads(t, workloads))
}

// The same limit applies to kubernetes_manifest, which leaves out a resource
// whose expansion is too large and reports it, like a typed resource.
func TestTerraformDirectory_GetWorkloads_ManifestOverrideCountsTowardsExpansionLimit(t *testing.T) {
	manifest := func(name, extra string) string {
		return `
resource "kubernetes_manifest" "big" {
  ` + extra + `
  manifest = {
    apiVersion = "v1"
    kind       = "ConfigMap"
    metadata   = { name = "` + name + `-${count.index}", namespace = "default" }
  }
}
`
	}
	padding := strings.Repeat("x", 20000)
	tests := []struct {
		name     string
		override string
		want     int
		bounded  bool
	}{
		{"small override expands", manifest("small", "count = 1000"), 1000, false},
		{"large override is bounded", manifest("large", "count = 1000\n  # "+padding), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, map[string]string{
				"main.tf":     manifest("base", "count = 1"),
				"override.tf": tt.override,
			})
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			if tt.bounded {
				require.Len(t, errs, 1)
				assert.ErrorContains(t, errs[0], "count or for_each expansion exceeds the size limit")
				resources, ok := onlyTerraformResourceErrors(errs)
				require.True(t, ok)
				assert.Equal(t, []string{"kubernetes_manifest.big"}, resources)
			} else {
				require.Empty(t, errs)
			}
			assert.Len(t, terraformOverrideWorkloads(t, workloads), tt.want)
		})
	}
}

func parseTerraformOverrideTest(t *testing.T, name, src string) *hcl.File {
	t.Helper()
	file, diags := hclparse.NewParser().ParseHCL([]byte(src), name)
	require.False(t, diags.HasErrors(), diags.Error())
	return file
}

func TestApplyTerraformOverrides_WithoutOverridesKeepsFiles(t *testing.T) {
	primary := []*hcl.File{parseTerraformOverrideTest(t, "main.tf", overrideBaseManifestPod)}
	result, errs := applyTerraformOverrides(primary, nil)
	require.Empty(t, errs)
	require.Len(t, result.files, 1)
	assert.Same(t, primary[0], result.files[0])
	assert.Empty(t, result.sourceSizes)
}

func TestApplyTerraformOverrides_DoesNotModifyParsedFiles(t *testing.T) {
	main := parseTerraformOverrideTest(t, "main.tf", overrideBaseManifestPod+`
locals {
  a = 1
}
`)
	override := parseTerraformOverrideTest(t, "override.tf", `
resource "kubernetes_manifest" "web" {
  manifest = {}
}
variable "host_network" {
  default = false
}
locals {
  a = 2
}
`)
	body := main.Body.(*hclsyntax.Body)
	blocks := append(hclsyntax.Blocks(nil), body.Blocks...)
	manifest := body.Blocks[1].Body.Attributes["manifest"]
	local := body.Blocks[2].Body.Attributes["a"]

	result, errs := applyTerraformOverrides([]*hcl.File{main}, []*hcl.File{override})
	require.Empty(t, errs)

	assert.Equal(t, blocks, body.Blocks)
	assert.Same(t, manifest, body.Blocks[1].Body.Attributes["manifest"])
	assert.Same(t, local, body.Blocks[2].Body.Attributes["a"])

	merged := result.files[0].Body.(*hclsyntax.Body)
	overrideBody := override.Body.(*hclsyntax.Body)
	assert.Same(t, overrideBody.Blocks[0].Body.Attributes["manifest"], merged.Blocks[1].Body.Attributes["manifest"])
	assert.Same(t, overrideBody.Blocks[2].Body.Attributes["a"], merged.Blocks[2].Body.Attributes["a"])
	// Variable overrides are applied to the collected variables, not merged
	// into the primary variable block.
	assert.Equal(t, []*hclsyntax.Block{overrideBody.Blocks[1]}, result.variables)
	assert.Same(t, body.Blocks[0], merged.Blocks[0])
	// The merged resource keeps the primary block's location.
	assert.Equal(t, body.Blocks[1].DefRange(), merged.Blocks[1].DefRange())
	assert.Equal(t, terraformBlockSpan(body.Blocks[1])+terraformBlockSpan(overrideBody.Blocks[0]),
		result.sourceSizes[merged.Blocks[1].Body])
}

func TestMergeTerraformBody(t *testing.T) {
	base := parseTerraformOverrideTest(t, "main.tf", `
a = 1
b = 2
port { n = 1 }
port { n = 2 }
dynamic "env" {
  for_each = []
  content {}
}
volume { n = 1 }
dynamic "mount" {
  for_each = []
  content {}
}
`).Body.(*hclsyntax.Body)
	override := parseTerraformOverrideTest(t, "override.tf", `
b = 3
c = 4
port { n = 3 }
env { n = 1 }
dynamic "volume" {
  for_each = []
  content {}
}
`).Body.(*hclsyntax.Body)

	merged := mergeTerraformBody(base, override)

	assert.Same(t, base.Attributes["a"], merged.Attributes["a"])
	assert.Same(t, override.Attributes["b"], merged.Attributes["b"])
	assert.Same(t, override.Attributes["c"], merged.Attributes["c"])

	var got []string
	for _, block := range merged.Blocks {
		got = append(got, strings.Join(append([]string{block.Type}, block.Labels...), " "))
	}
	// Both base port blocks are replaced by the override's; a static env
	// block replaces dynamic "env", and dynamic "volume" the static volume
	// block. The block type that is not overridden is kept, first.
	assert.Equal(t, []string{"dynamic mount", "port", "env", "dynamic volume"}, got)
	assert.Same(t, override.Blocks[0], merged.Blocks[1])
}

// The default Terraform substitutes for a null variable file value is the
// declaration default converted to the type, while a variable that is not set
// at all also gets the optional attribute defaults (PrepareFinalInputVariableValue).
func TestTerraformDirectory_GetWorkloads_OverrideVariableNullInput(t *testing.T) {
	const manifest = `
resource "kubernetes_manifest" "pod" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "pod", namespace = "default" }
    spec       = { securityContext = var.sc }
  }
}
`
	const primary = `
variable "sc" {
  type     = object({ privileged = optional(bool, false) })
  nullable = false
}
` + manifest
	tests := []struct {
		name     string
		files    map[string]string
		expected interface{}
	}{
		{
			name: "omitted input gets the optional attribute defaults",
			files: map[string]string{
				"main.tf":     primary,
				"override.tf": "variable \"sc\" {\n  default = {}\n}\n",
			},
			expected: false,
		},
		{
			name: "explicit null input gets the overridden default as converted",
			files: map[string]string{
				"main.tf":          primary,
				"override.tf":      "variable \"sc\" {\n  default = {}\n}\n",
				"terraform.tfvars": `sc = null`,
			},
			expected: nil,
		},
		{
			// An override that sets the type as well decodes its default with
			// that type's optional attribute defaults.
			name: "explicit null input gets an override default decoded with its own type",
			files: map[string]string{
				"main.tf":          primary,
				"override.tf":      "variable \"sc\" {\n  type    = object({ privileged = optional(bool, true) })\n  default = {}\n}\n",
				"terraform.tfvars": `sc = null`,
			},
			expected: true,
		},
		{
			// A type-only override keeps the primary default as decoded, with
			// the primary type's optional attribute defaults.
			name: "explicit null input gets the primary default after a type-only override",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type     = object({ privileged = optional(bool, false) })
  default  = {}
  nullable = false
}
` + manifest,
				"override.tf":      "variable \"sc\" {\n  type = object({ privileged = optional(bool, true) })\n}\n",
				"terraform.tfvars": `sc = null`,
			},
			expected: false,
		},
		{
			// Terraform applies the optional attribute defaults when decoding
			// a primary default, so it already holds them.
			name: "explicit null input gets the primary default as decoded",
			files: map[string]string{
				"main.tf": `
variable "sc" {
  type     = object({ privileged = optional(bool, false) })
  default  = {}
  nullable = false
}
` + manifest,
				"terraform.tfvars": `sc = null`,
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, tt.files)
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.Empty(t, errs)
			all := terraformOverrideWorkloads(t, workloads)
			require.Len(t, all, 1)
			securityContext, ok := podSpec(t, all[0])["securityContext"].(map[string]interface{})
			require.True(t, ok, "securityContext must be an object")
			require.Contains(t, securityContext, "privileged")
			assert.Equal(t, tt.expected, securityContext["privileged"])
		})
	}

	t.Run("ordinary default replaces an explicit null input", func(t *testing.T) {
		dir := t.TempDir()
		writeTerraformOverrideFiles(t, dir, map[string]string{
			"main.tf":          overrideBaseManifestPod,
			"override.tf":      "variable \"host_network\" {\n  default  = false\n  nullable = false\n}\n",
			"terraform.tfvars": `host_network = null`,
		})
		workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
		require.Empty(t, errs)
		all := terraformOverrideWorkloads(t, workloads)
		require.Len(t, all, 1)
		assert.Equal(t, false, podSpec(t, all[0])["hostNetwork"])
	})
}

func TestTerraformTypeConstraint(t *testing.T) {
	tests := []struct {
		expr    string
		want    cty.Type
		invalid bool
	}{
		{expr: "list", want: cty.List(cty.DynamicPseudoType)},
		{expr: "map", want: cty.Map(cty.DynamicPseudoType)},
		{expr: "list(string)", want: cty.List(cty.String)},
		{expr: "map(number)", want: cty.Map(cty.Number)},
		{expr: "string", want: cty.String},
		{expr: "any", want: cty.DynamicPseudoType},
		{expr: "object({ a = list(bool) })", want: cty.Object(map[string]cty.Type{"a": cty.List(cty.Bool)})},
		// The shorthands are only accepted as the whole type constraint.
		{expr: "list(list)", invalid: true},
		{expr: "map(map)", invalid: true},
		{expr: "object({ a = list })", invalid: true},
		{expr: "boool", invalid: true},
		{expr: "list(boool)", invalid: true},
		{expr: `"list"`, invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			expr, diags := hclsyntax.ParseExpression([]byte(tt.expr), "test.tf", hcl.InitialPos)
			require.False(t, diags.HasErrors(), diags.Error())
			ty, _, diags := terraformTypeConstraint(expr)
			if tt.invalid {
				assert.True(t, diags.HasErrors())
				return
			}
			require.False(t, diags.HasErrors(), diags.Error())
			assert.True(t, tt.want.Equals(ty), "got %s", ty.FriendlyName())
		})
	}
}

// The list and map shorthands are valid type constraints in a primary file and
// in an override file alike.
func TestTerraformDirectory_GetWorkloads_VariableTypeShorthand(t *testing.T) {
	const manifest = `
resource "kubernetes_manifest" "pod" {
  manifest = {
    apiVersion = "v1"
    kind       = "Pod"
    metadata   = { name = "pod", namespace = "default", labels = var.labels }
    spec       = { containers = [{ name = "app", image = "nginx:1.25", args = var.args }] }
  }
}
`
	tests := []struct {
		name  string
		files map[string]string
	}{
		{
			name: "override file",
			files: map[string]string{
				"main.tf": "variable \"args\" {\n  default = [\"x\"]\n}\nvariable \"labels\" {\n  default = {}\n}\n" + manifest,
				"override.tf": `
variable "args" {
  type    = list
  default = ["a", "b"]
}
variable "labels" {
  type    = map
  default = { team = "web" }
}
`,
			},
		},
		{
			name: "primary file",
			files: map[string]string{
				"main.tf": `
variable "args" {
  type    = list
  default = ["a", "b"]
}
variable "labels" {
  type    = map
  default = { team = "web" }
}
` + manifest,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, tt.files)
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.Empty(t, errs)
			all := terraformOverrideWorkloads(t, workloads)
			require.Len(t, all, 1)
			metadata := all[0].GetObject()["metadata"].(map[string]interface{})
			assert.Equal(t, map[string]interface{}{"team": "web"}, metadata["labels"])
			containers := podSpec(t, all[0])["containers"].([]interface{})
			require.Len(t, containers, 1)
			assert.Equal(t, []interface{}{"a", "b"}, containers[0].(map[string]interface{})["args"])
		})
	}

	t.Run("shorthand type still rejects a default of another kind", func(t *testing.T) {
		variable := newTerraformVariable(parseTerraformAttribute(t, `type = list`))
		_, err := variable.convert(cty.StringVal("x"))
		assert.Error(t, err)
	})
}

// parseTerraformAttribute parses one attribute, such as `nullable = false`.
func parseTerraformAttribute(t *testing.T, src string) *hcl.Attribute {
	t.Helper()
	body := parseTerraformOverrideTest(t, "test.tf", src).Body.(*hclsyntax.Body)
	require.Len(t, body.Attributes, 1)
	for _, attr := range body.Attributes {
		return attr.AsHCLAttribute()
	}
	return nil
}

func TestTerraformVariableNonNullable(t *testing.T) {
	tests := []struct {
		src             string
		wantNonNullable bool
		wantOK          bool
	}{
		{src: `nullable = false`, wantNonNullable: true, wantOK: true},
		{src: `nullable = true`, wantNonNullable: false, wantOK: true},
		{src: `nullable = "false"`, wantNonNullable: true, wantOK: true},
		{src: `nullable = "true"`, wantNonNullable: false, wantOK: true},
		{src: `nullable = "maybe"`},
		{src: `nullable = 0`},
		{src: `nullable = [false]`},
		{src: `nullable = null`},
		{src: `nullable = var.unknown`},
	}
	for _, tt := range tests {
		t.Run(tt.src, func(t *testing.T) {
			nonNullable, ok := terraformVariableNonNullable(parseTerraformAttribute(t, tt.src))
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantNonNullable, nonNullable)
		})
	}

	t.Run("string nullable applies to a null variable file value", func(t *testing.T) {
		for _, files := range []map[string]string{
			{
				"main.tf":          "variable \"host_network\" {\n  type     = bool\n  default  = false\n  nullable = \"false\"\n}\n" + overrideBaseManifestPod[strings.Index(overrideBaseManifestPod, "resource"):],
				"terraform.tfvars": `host_network = null`,
			},
			{
				"main.tf":          overrideBaseManifestPod,
				"override.tf":      "variable \"host_network\" {\n  default  = false\n  nullable = \"false\"\n}\n",
				"terraform.tfvars": `host_network = null`,
			},
		} {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, files)
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.Empty(t, errs)
			all := terraformOverrideWorkloads(t, workloads)
			require.Len(t, all, 1)
			assert.Equal(t, false, podSpec(t, all[0])["hostNetwork"])
		}
	})
}

// Local values from several override blocks and files are applied in order
// to one copy of each primary locals block, a later override winning.
func TestApplyTerraformOverrides_MultipleLocalsOverrides(t *testing.T) {
	main := parseTerraformOverrideTest(t, "main.tf", `
locals {
  a = 1
  b = 1
  c = 1
  d = 1
}
locals {
  e = 1
}
`)
	first := parseTerraformOverrideTest(t, "a_override.tf", `
locals {
  a = 2
  b = 2
}
locals {
  e = 2
}
`)
	second := parseTerraformOverrideTest(t, "b_override.tf", `
locals {
  b = 3
  c = 3
}
`)
	body := main.Body.(*hclsyntax.Body)
	original := []hclsyntax.Attributes{maps.Clone(body.Blocks[0].Body.Attributes), maps.Clone(body.Blocks[1].Body.Attributes)}

	result, errs := applyTerraformOverrides([]*hcl.File{main}, []*hcl.File{first, second})
	require.Empty(t, errs)

	firstBody := first.Body.(*hclsyntax.Body)
	secondBody := second.Body.(*hclsyntax.Body)
	merged := result.files[0].Body.(*hclsyntax.Body)
	require.Len(t, merged.Blocks, 2)
	attrs := merged.Blocks[0].Body.Attributes
	assert.Same(t, firstBody.Blocks[0].Body.Attributes["a"], attrs["a"])
	assert.Same(t, secondBody.Blocks[0].Body.Attributes["b"], attrs["b"], "the later override file wins")
	assert.Same(t, secondBody.Blocks[0].Body.Attributes["c"], attrs["c"])
	assert.Same(t, original[0]["d"], attrs["d"])
	assert.Same(t, firstBody.Blocks[1].Body.Attributes["e"], merged.Blocks[1].Body.Attributes["e"])

	// The parsed primary file is unchanged.
	assert.Equal(t, original[0], body.Blocks[0].Body.Attributes)
	assert.Equal(t, original[1], body.Blocks[1].Body.Attributes)
	assert.NotSame(t, body.Blocks[0], merged.Blocks[0])

	// Evaluated, the later override wins.
	locals, _ := resolveLocals(result.files, nil)
	for name, want := range map[string]int64{"a": 2, "b": 3, "c": 3, "d": 1, "e": 2} {
		got, _ := locals[name].AsBigFloat().Int64()
		assert.Equal(t, want, got, name)
	}
}

// A resource merged by several override files keeps one source size entry,
// for its final body, holding the size of every block it was built from.
func TestApplyTerraformOverrides_SourceSizesOfRepeatedOverrides(t *testing.T) {
	const resource = `
resource "kubernetes_manifest" "web" {
  manifest = {}
}
`
	main := parseTerraformOverrideTest(t, "main.tf", resource)
	first := parseTerraformOverrideTest(t, "a_override.tf", resource)
	second := parseTerraformOverrideTest(t, "b_override.tf", `
resource "kubernetes_manifest" "web" {
  manifest = { apiVersion = "v1" }
}
`)
	result, errs := applyTerraformOverrides([]*hcl.File{main}, []*hcl.File{first, second})
	require.Empty(t, errs)

	merged := result.files[0].Body.(*hclsyntax.Body).Blocks[0]
	block := func(f *hcl.File) *hclsyntax.Block { return f.Body.(*hclsyntax.Body).Blocks[0] }
	assert.Equal(t, map[*hclsyntax.Body]int{
		merged.Body: terraformBlockSpan(block(main)) + terraformBlockSpan(block(first)) + terraformBlockSpan(block(second)),
	}, result.sourceSizes)
}
