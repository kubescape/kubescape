package cautils

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// moduleAppTerraform is a module that turns its inputs into one Deployment.
const moduleAppTerraform = `
variable "name" {
  type    = string
  default = "app"
}

variable "privileged" {
  type    = bool
  default = false
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name = var.name
  }
  spec {
    selector {
      match_labels = { app = var.name }
    }
    template {
      metadata {
        labels = { app = var.name }
      }
      spec {
        container {
          name  = "app"
          image = "nginx:1.27.0"
          security_context {
            privileged = var.privileged
          }
        }
      }
    }
  }
}
`

func writeTerraformTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	return dir
}

// privilegedByDeployment maps each Deployment's name to its container's
// securityContext.privileged value.
func privilegedByDeployment(t *testing.T, workloads map[string][]workloadinterface.IMetadata) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	for _, list := range workloads {
		for _, w := range list {
			if w.GetKind() != "Deployment" {
				continue
			}
			spec := w.GetObject()["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})
			container := spec["containers"].([]interface{})[0].(map[string]interface{})
			sc, _ := container["securityContext"].(map[string]interface{})
			out[w.GetName()] = sc["privileged"]
		}
	}
	return out
}

func TestTerraformModuleCallPassesItsValues(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "app" {
  source     = "./modules/app"
  name       = "web"
  privileged = true
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"web": true}, privilegedByDeployment(t, workloads),
		"the module is scanned with the values its caller passes, not on its own with its defaults")
}

func TestTerraformModuleCallValuesFromRootVariablesAndLocals(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
variable "privileged" {
  type    = bool
  default = false
}

locals {
  name = "web-${var.env}"
}

variable "env" {
  type    = string
  default = "dev"
}

module "app" {
  source     = "./modules/app"
  name       = local.name
  privileged = var.privileged
}
`,
		"terraform.tfvars":    "privileged = true\nenv = \"prod\"\n",
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"web-prod": true}, privilegedByDeployment(t, workloads))
}

func TestTerraformModuleCalledTwiceGivesOneObjectPerCall(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "prod" {
  source     = "./modules/app"
  name       = "prod"
  privileged = true
}

module "dev" {
  source = "./modules/app"
  name   = "dev"
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, _, locations, err := LoadResourcesFromTerraformWithLocations(context.Background(), dir, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"prod": true, "dev": false}, privilegedByDeployment(t, workloads))

	moduleFile := filepath.Join(dir, "modules", "app", "main.tf")
	var paths []string
	for _, list := range workloads {
		for _, w := range list {
			if lw, ok := w.(interface{ GetPath() string }); ok {
				paths = append(paths, lw.GetPath())
			}
		}
	}
	assert.ElementsMatch(t, []string{moduleFile + ":0", moduleFile + ":1"}, paths, "each call keeps its own workload path")
	for _, p := range paths {
		assert.Equal(t, 12, locations[p].Line, "both point at the resource block in the module")
	}
}

func TestTerraformModuleCallWithUnresolvedValueLeavesOutOnlyTheResourcesUsingIt(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
variable "privileged" {
  type = bool
}

module "app" {
  source     = "./modules/app"
  name       = "web"
  privileged = var.privileged
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), dir, nil)
	require.NoError(t, err)
	assert.Empty(t, privilegedByDeployment(t, workloads),
		"the module's default must not stand in for a value the caller passes")
	require.Len(t, skips, 1, "the resource left out is reported, so coverage is marked incomplete")
	assert.Equal(t, filepath.Join(dir, "modules", "app"), skips[0].Path)
	assert.Equal(t, []string{"kubernetes_deployment_v1.app"}, skips[0].Resources)
}

// deploymentCount counts the Deployments in workloads, to catch a module that
// is scanned twice.
func deploymentCount(workloads map[string][]workloadinterface.IMetadata) int {
	n := 0
	for _, list := range workloads {
		for _, w := range list {
			if w.GetKind() == "Deployment" {
				n++
			}
		}
	}
	return n
}

func TestTerraformModuleCallWithForEach(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "app" {
  for_each   = { api = true, web = false }
  source     = "./modules/app"
  name       = each.key
  privileged = each.value
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"api": true, "web": false}, privilegedByDeployment(t, workloads))
}

func TestTerraformScanRootCalledByAnExampleIsScannedOnItsOwn(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": moduleAppTerraform,
		"examples/basic/main.tf": `
module "app" {
  source     = "../../"
  name       = "example"
  privileged = true
}
`,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"app": false}, privilegedByDeployment(t, workloads),
		"the directory the scan starts on is scanned as before, not through an example below it")
	assert.Equal(t, 1, deploymentCount(workloads))
}

func TestTerraformModuleFallbackWaitsForItsCaller(t *testing.T) {
	// modules/a sorts before modules/x, but x calls a: a must be rendered
	// through x's call once x is scanned on its own, not also on its own.
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
variable "replicas" {
  type = number
}

module "x" {
  count  = var.replicas
  source = "./modules/x"
}
`,
		"modules/x/main.tf": `
module "a" {
  source     = "../a"
  name       = "from-x"
  privileged = true
}
`,
		"modules/a/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"from-x": true}, privilegedByDeployment(t, workloads))
	assert.Equal(t, 1, deploymentCount(workloads))
}

func TestTerraformModuleCalledFromTwoRoots(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"prod/main.tf": `
module "app" {
  source     = "../modules/app"
  name       = "prod"
  privileged = true
}
`,
		"dev/main.tf": `
module "app" {
  source = "../modules/app"
  name   = "dev"
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"prod": true, "dev": false}, privilegedByDeployment(t, workloads))
	assert.Equal(t, 2, deploymentCount(workloads))
}

func TestTerraformModuleCallWithCount(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "app" {
  count      = 2
  source     = "./modules/app"
  name       = "web-${count.index}"
  privileged = count.index == 1
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"web-0": false, "web-1": true}, privilegedByDeployment(t, workloads))
}

func TestTerraformNestedModuleCallsPassValuesDown(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "platform" {
  source     = "./modules/platform"
  privileged = true
}
`,
		"modules/platform/main.tf": `
variable "privileged" {
  type    = bool
  default = false
}

module "app" {
  source     = "../app"
  name       = "nested"
  privileged = var.privileged
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"nested": true}, privilegedByDeployment(t, workloads))
}

func TestTerraformCalledModuleIgnoresItsOwnTfvars(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "app" {
  source     = "./modules/app"
  privileged = true
}
`,
		"modules/app/main.tf":          moduleAppTerraform,
		"modules/app/terraform.tfvars": "privileged = false\nname = \"from-tfvars\"\n",
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"app": true}, privilegedByDeployment(t, workloads),
		"Terraform reads tfvars files for the root module only")
}

func TestTerraformUncalledModuleIsStillScannedOnItsOwn(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "remote" {
  source = "terraform-aws-modules/eks/aws"
}
`,
		"modules/app/main.tf": moduleAppTerraform,
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"app": false}, privilegedByDeployment(t, workloads),
		"a module nothing calls by a local path is scanned with its defaults, as before")
}

func TestTerraformCalledModuleIsScannedOnItsOwnWhenItsCallerFails(t *testing.T) {
	parent := writeTerraformTree(t, map[string]string{
		"infra/main.tf": `
module "app" {
  source     = "../modules/app"
  privileged = true
}
`,
		"infra/broken.tf":     `resource "kubernetes_deployment_v1" "broken" {`,
		"modules/app/main.tf": moduleAppTerraform,
	})
	workloads, skips, err := LoadResourcesFromTerraformFilteredWithSkips(context.Background(), parent, nil)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"app": false}, privilegedByDeployment(t, workloads),
		"when the caller can't be rendered, the module is scanned on its own as before rather than left out")
	require.Len(t, skips, 1)
	assert.Equal(t, filepath.Join(parent, "infra"), skips[0].Path)
}

func TestTerraformModuleCallLoopStops(t *testing.T) {
	dir := writeTerraformTree(t, map[string]string{
		"main.tf": `
module "a" {
  source = "./modules/a"
}
`,
		"modules/a/main.tf": `
module "b" {
  source = "../b"
}
`,
		"modules/b/main.tf": `
module "a" {
  source = "../a"
}
` + strings.Replace(moduleAppTerraform, `default = "app"`, `default = "b"`, 1),
	})

	workloads, err := LoadResourcesFromTerraform(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"b": false}, privilegedByDeployment(t, workloads))
}
