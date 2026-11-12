package cautils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTerraformFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
}

func terraformObject(t *testing.T, dir string) (map[string]interface{}, []error) {
	t.Helper()
	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	wls := workloads[filepath.Join(dir, "main.tf")]
	require.Len(t, wls, 1)
	return wls[0].GetObject(), errs
}

func terraformFirstContainer(t *testing.T, obj map[string]interface{}) map[string]interface{} {
	t.Helper()
	containers, ok := obj["spec"].(map[string]interface{})["containers"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, containers)
	return containers[0].(map[string]interface{})
}

const terraformPodUsingVars = `
resource "kubernetes_pod_v1" "app" {
  metadata {
    name = var.name
  }
  spec {
    container {
      name  = "app"
      image = var.image
      security_context {
        privileged = var.privileged
      }
    }
  }
}
`

func TestTerraformDirectory_GetWorkloads_VarFiles(t *testing.T) {
	tests := []struct {
		name           string
		files          map[string]string
		wantName       string
		wantImage      string
		wantPrivileged interface{}
	}{
		{
			name: "defaults only",
			files: map[string]string{
				"variables.tf": `
variable "name" { default = "app" }
variable "image" { default = "nginx:1.27" }
variable "privileged" { default = false }
`,
			},
			wantName:       "app",
			wantImage:      "nginx:1.27",
			wantPrivileged: false,
		},
		{
			name: "terraform.tfvars overrides defaults and sets variables without one",
			files: map[string]string{
				"variables.tf": `
variable "name" { default = "app" }
variable "image" {}
variable "privileged" { default = false }
`,
				"terraform.tfvars": `
image      = "nginx:1.27"
privileged = true
`,
			},
			wantName:       "app",
			wantImage:      "nginx:1.27",
			wantPrivileged: true,
		},
		{
			name: "auto tfvars apply after terraform.tfvars in lexical order",
			files: map[string]string{
				"variables.tf": `
variable "name" {}
variable "image" {}
variable "privileged" {}
`,
				"terraform.tfvars":      `name = "base"` + "\nimage = \"nginx:1.0\"\nprivileged = false\n",
				"terraform.tfvars.json": `{"name": "from-json"}`,
				"b.auto.tfvars":         `image = "nginx:2.0"`,
				"a.auto.tfvars.json":    `{"image": "nginx:1.5", "privileged": true}`,
			},
			wantName:       "from-json",
			wantImage:      "nginx:2.0",
			wantPrivileged: true,
		},
		{
			name: "undeclared and non-auto files are ignored",
			files: map[string]string{
				"variables.tf": `
variable "name" { default = "app" }
variable "image" { default = "nginx:1.27" }
variable "privileged" { default = false }
`,
				"terraform.tfvars": `
undeclared = "x"
`,
				"prod.tfvars": `privileged = true`,
			},
			wantName:       "app",
			wantImage:      "nginx:1.27",
			wantPrivileged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.files["main.tf"] = terraformPodUsingVars
			writeTerraformFiles(t, dir, tt.files)

			obj, errs := terraformObject(t, dir)
			require.Empty(t, errs)
			assert.Equal(t, tt.wantName, obj["metadata"].(map[string]interface{})["name"])
			container := terraformFirstContainer(t, obj)
			assert.Equal(t, tt.wantImage, container["image"])
			assert.Equal(t, tt.wantPrivileged, container["securityContext"].(map[string]interface{})["privileged"])
		})
	}
}

func TestTerraformDirectory_GetWorkloads_InvalidVarFile(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf":          terraformPodUsingVars,
		"variables.tf":     "variable \"name\" { default = \"app\" }\nvariable \"image\" { default = \"nginx\" }\nvariable \"privileged\" { default = false }\n",
		"terraform.tfvars": `image = `,
	})

	obj, errs := terraformObject(t, dir)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "terraform.tfvars")
	assert.Equal(t, "nginx", terraformFirstContainer(t, obj)["image"])
}

func TestTerraformDirectory_GetWorkloads_VarFileOutsideWorkspace(t *testing.T) {
	outside := t.TempDir()
	dir := t.TempDir()
	writeTerraformFiles(t, outside, map[string]string{"terraform.tfvars": `privileged = true`})
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf":      terraformPodUsingVars,
		"variables.tf": "variable \"name\" { default = \"app\" }\nvariable \"image\" { default = \"nginx\" }\nvariable \"privileged\" { default = false }\n",
	})
	require.NoError(t, os.Symlink(filepath.Join(outside, "terraform.tfvars"), filepath.Join(dir, "terraform.tfvars")))

	workloads, errs := NewTerraformDirectory(dir, dir).GetWorkloads(dir)
	require.Empty(t, errs)
	wls := workloads[filepath.Join(dir, "main.tf")]
	require.Len(t, wls, 1)
	container := terraformFirstContainer(t, wls[0].GetObject())
	assert.Equal(t, false, container["securityContext"].(map[string]interface{})["privileged"])
}

func TestTerraformDirectory_GetWorkloads_Locals(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_pod_v1" "app" {
  metadata {
    name   = local.name
    labels = local.labels
  }
  spec {
    host_network = local.host_network
    container {
      name  = "app"
      image = local.image
    }
  }
}
`,
		"locals.tf": `
locals {
  image  = "${local.registry}/app:${var.tag}"
  labels = { app = local.name, env = var.env }
}

locals {
  name         = "app-${var.env}"
  registry     = try(local.registry_override, "docker.io/acme")
  registry_override = local.org_registry
  org_registry = "ghcr.io/acme"
  host_network = var.env == "prod" ? false : true
}
`,
		"variables.tf": `
variable "tag" { default = "1.2.3" }
variable "env" { default = "dev" }
`,
		"terraform.tfvars": `env = "prod"`,
	})

	obj, errs := terraformObject(t, dir)
	require.Empty(t, errs)
	meta := obj["metadata"].(map[string]interface{})
	assert.Equal(t, "app-prod", meta["name"])
	assert.Equal(t, map[string]interface{}{"app": "app-prod", "env": "prod"}, meta["labels"])
	assert.Equal(t, false, obj["spec"].(map[string]interface{})["hostNetwork"])
	assert.Equal(t, "ghcr.io/acme/app:1.2.3", terraformFirstContainer(t, obj)["image"])
}

func TestTerraformDirectory_GetWorkloads_UnresolvableLocal(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
locals {
  a     = local.b
  b     = local.a
  image = data.registry.image
  name  = "app"
}

resource "kubernetes_pod_v1" "app" {
  metadata {
    name = local.name
  }
  spec {
    container {
      name  = "app"
      image = local.image
    }
  }
}
`,
	})

	obj, errs := terraformObject(t, dir)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `"image"`)
	assert.Equal(t, "app", obj["metadata"].(map[string]interface{})["name"])
	assert.NotContains(t, terraformFirstContainer(t, obj), "image")
}

func TestTerraformDirectory_GetWorkloads_Functions(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
variable "settings" {
  default = { replicas = "3", team = "Platform_Ops" }
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name   = lower(replace(var.settings.team, "/[^A-Za-z0-9]+/", "-"))
    labels = merge({ app = "web" }, { team = lookup(var.settings, "team", "none") })
    annotations = {
      config  = jsonencode({ debug = false })
      encoded = base64encode("hello")
      decoded = base64decode("aGVsbG8=")
      size    = tostring(length("abcd"))
      missing = try(var.settings.owner, "unknown")
      first   = coalesce("", null, "nginx:1.27")
      team    = lookup(var.settings, "team")
    }
  }
  spec {
    replicas = tonumber(var.settings.replicas)
    template {
      metadata {}
      spec {
        container {
          name  = "web"
          image = format("%s:%s", "nginx", join(".", ["1", "27"]))
          args  = concat(["--port"], [tostring(max(80, 8080))])
        }
      }
    }
  }
}
`,
	})

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	wls := workloads[filepath.Join(dir, "main.tf")]
	require.Len(t, wls, 1)
	obj := wls[0].GetObject()

	meta := obj["metadata"].(map[string]interface{})
	assert.Equal(t, "platform-ops", meta["name"])
	assert.Equal(t, map[string]interface{}{"app": "web", "team": "Platform_Ops"}, meta["labels"])
	assert.Equal(t, map[string]interface{}{
		"config":  `{"debug":false}`,
		"encoded": "aGVsbG8=",
		"decoded": "hello",
		"size":    "4",
		"missing": "unknown",
		"first":   "nginx:1.27",
		"team":    "Platform_Ops",
	}, meta["annotations"])

	spec := obj["spec"].(map[string]interface{})
	assert.Equal(t, json.Number("3"), spec["replicas"])
	container := terraformFirstContainer(t, spec["template"].(map[string]interface{}))
	assert.Equal(t, "nginx:1.27", container["image"])
	assert.Equal(t, []interface{}{"--port", "8080"}, container["args"])
}

func TestTerraformDirectory_GetWorkloads_VariableTypes(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_pod_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    host_network = var.network.host
    container {
      name  = "app"
      image = "nginx:1.27"
      security_context {
        privileged = var.privileged == true
      }
    }
  }
}
`,
		"variables.tf": `
variable "privileged" {
  type = bool
}

variable "network" {
  type    = object({ host = optional(bool, true) })
  default = {}
}
`,
		"terraform.tfvars": `privileged = "true"`,
	})

	obj, errs := terraformObject(t, dir)
	require.Empty(t, errs)
	assert.Equal(t, true, obj["spec"].(map[string]interface{})["hostNetwork"])
	assert.Equal(t, true, terraformFirstContainer(t, obj)["securityContext"].(map[string]interface{})["privileged"])
}

func TestTerraformDirectory_GetWorkloads_VarFileTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf":          terraformPodUsingVars,
		"variables.tf":     "variable \"name\" { default = \"app\" }\nvariable \"image\" { default = \"nginx\" }\nvariable \"privileged\" {\n  type    = bool\n  default = false\n}\n",
		"terraform.tfvars": `privileged = "maybe"`,
	})

	obj, errs := terraformObject(t, dir)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `variable "privileged"`)
	assert.Equal(t, false, terraformFirstContainer(t, obj)["securityContext"].(map[string]interface{})["privileged"])
}

func TestTerraformDirectory_GetWorkloads_LookupMissingKey(t *testing.T) {
	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"main.tf": `
resource "kubernetes_pod_v1" "app" {
  metadata {
    name = lookup({ team = "ops" }, "owner")
  }
  spec {
    container {
      name  = "app"
      image = "nginx:1.27"
    }
  }
}
`,
	})

	obj, errs := terraformObject(t, dir)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `"owner"`)
	assert.Equal(t, "app", obj["metadata"].(map[string]interface{})["name"])
}

func TestTerraformDirectory_GetWorkloads_LocalSizeLimit(t *testing.T) {
	var locals strings.Builder
	locals.WriteString("locals {\n  l0 = [\"x\"]\n")
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&locals, "  l%d = concat(local.l%d, local.l%d)\n", i, i-1, i-1)
	}
	locals.WriteString("}\n")

	dir := t.TempDir()
	writeTerraformFiles(t, dir, map[string]string{
		"locals.tf": locals.String(),
		"main.tf": `
resource "kubernetes_pod_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    container {
      name  = "app"
      image = "nginx:1.27"
      args  = local.l40
    }
  }
}
`,
	})

	obj, errs := terraformObject(t, dir)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `"args"`)
	assert.NotContains(t, terraformFirstContainer(t, obj), "args")
}
