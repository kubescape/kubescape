package cautils

import (
	"context"
	"encoding/json"
	"errors"
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
	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
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
		loc, ok := TerraformSourceLocation(terraformWorkloadPath(main, i))
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
			require.Empty(t, errs)
			all := terraformOverrideWorkloads(t, workloads)
			if tt.expected == nil {
				assert.Empty(t, all)
				return
			}
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

// Unmatched overrides follow the existing error policy: a directly scanned
// directory reports the error, a nested one is skipped with a warning.
func TestLoadResourcesFromTerraform_UnmatchedOverride(t *testing.T) {
	root := resolvedTempDir(t)
	nested := filepath.Join(root, "modules", "app")
	require.NoError(t, os.MkdirAll(nested, 0o700))
	writeTerraformOverrideFiles(t, nested, map[string]string{
		"main.tf":     overrideBaseManifestPod,
		"override.tf": `resource "kubernetes_manifest" "missing" {}`,
	})

	_, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), root, nil, root)
	require.NoError(t, err)
	require.Len(t, skips, 1)
	assert.Equal(t, nested, skips[0].Path)

	_, _, err = LoadResourcesFromTerraformFilteredWithSkips(context.Background(), nested, nil, root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `there is no kubernetes_manifest resource named "missing"`)
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

// The same limit applies to kubernetes_manifest, which skips a resource whose
// expansion is too large with a warning.
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
	}{
		{"small override expands", manifest("small", "count = 1000"), 1000},
		{"large override is bounded", manifest("large", "count = 1000\n  # "+padding), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTerraformOverrideFiles(t, dir, map[string]string{
				"main.tf":     manifest("base", "count = 1"),
				"override.tf": tt.override,
			})
			workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
			require.Empty(t, errs)
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
