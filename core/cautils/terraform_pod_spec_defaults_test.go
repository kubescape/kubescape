package cautils

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestIsPodSpecBlockPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"kubernetes_pod_v1.web.spec", true},
		{"kubernetes_pod.web.spec", true},
		{"kubernetes_deployment_v1.web.spec.template.spec", true},
		{"kubernetes_stateful_set_v1.db.spec.template.spec", true},
		{"kubernetes_daemonset.agent.spec.template.spec", true},
		{"kubernetes_job_v1.migrate.spec.template.spec", true},
		{"kubernetes_cron_job_v1.backup.spec.job_template.spec.template.spec", true},
		{"kubernetes_deployment_v1.web.spec", false},
		{"kubernetes_pod_v1.web.spec.container", false},
		{"kubernetes_cron_job_v1.backup.spec.job_template.spec", false},
		{"kubernetes_stateful_set_v1.db.spec.volume_claim_template.spec", false},
		{"kubernetes_service_v1.web.spec", false},
		{"kubernetes_manifest.web.spec", false},
		{"spec", false},
		{"kubernetes_pod_v1", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, isPodSpecBlockPath(tc.path))
		})
	}
}

func podSpecAt(t *testing.T, manifest map[string]interface{}, path ...string) map[string]interface{} {
	t.Helper()
	cur := manifest
	for _, key := range path {
		next, ok := cur[key].(map[string]interface{})
		require.True(t, ok, "missing %q in %v", key, path)
		cur = next
	}
	return cur
}

const podBearingTerraform = `
resource "kubernetes_pod_v1" "pod" {
  spec {
    container {
      name  = "app"
      image = "nginx"
    }
  }
}

resource "kubernetes_deployment_v1" "deployment" {
  spec {
    template {
      spec {
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_stateful_set_v1" "statefulset" {
  spec {
    service_name = "db"
    template {
      spec {
        container {
          name  = "db"
          image = "postgres"
        }
      }
    }
    volume_claim_template {
      metadata {
        name = "data"
      }
      spec {
        access_modes = ["ReadWriteOnce"]
      }
    }
  }
}

resource "kubernetes_daemon_set_v1" "daemonset" {
  spec {
    template {
      spec {
        container {
          name  = "agent"
          image = "agent"
        }
      }
    }
  }
}

resource "kubernetes_job_v1" "job" {
  spec {
    template {
      spec {
        container {
          name  = "migrate"
          image = "migrate"
        }
      }
    }
  }
}

resource "kubernetes_cron_job_v1" "cronjob" {
  spec {
    schedule = "0 * * * *"
    job_template {
      spec {
        template {
          spec {
            container {
              name  = "backup"
              image = "backup"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "service" {
  spec {
    selector = { app = "web" }
  }
}
`

// TestExtractTypedResourcesDefaultsAutomountServiceAccountToken covers every
// pod-bearing kind: the provider sends automountServiceAccountToken: true for a
// pod spec that leaves it out, so the manifest has to say so too.
func TestExtractTypedResourcesDefaultsAutomountServiceAccountToken(t *testing.T) {
	byName := typedManifestsByName(t, podBearingTerraform)

	for name, path := range map[string][]string{
		"Pod/pod":                 {"spec"},
		"Deployment/deployment":   {"spec", "template", "spec"},
		"StatefulSet/statefulset": {"spec", "template", "spec"},
		"DaemonSet/daemonset":     {"spec", "template", "spec"},
		"Job/job":                 {"spec", "template", "spec"},
		"CronJob/cronjob":         {"spec", "jobTemplate", "spec", "template", "spec"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Contains(t, byName, name)
			assert.Equal(t, true, podSpecAt(t, byName[name], path...)["automountServiceAccountToken"])
		})
	}

	t.Run("only the pod spec gets the default", func(t *testing.T) {
		assert.NotContains(t, podSpecAt(t, byName["Deployment/deployment"], "spec"), "automountServiceAccountToken")
		assert.NotContains(t, podSpecAt(t, byName["Service/service"], "spec"), "automountServiceAccountToken")
		claim := byName["StatefulSet/statefulset"]["spec"].(map[string]interface{})["volumeClaimTemplates"].([]interface{})[0].(map[string]interface{})
		assert.NotContains(t, claim["spec"].(map[string]interface{}), "automountServiceAccountToken")
	})
}

func TestExtractTypedResourcesKeepsDeclaredAutomountServiceAccountToken(t *testing.T) {
	src := `
resource "kubernetes_deployment_v1" "off" {
  spec {
    template {
      spec {
        automount_service_account_token = false
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_deployment_v1" "on" {
  spec {
    template {
      spec {
        automount_service_account_token = true
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_deployment_v1" "null" {
  spec {
    template {
      spec {
        automount_service_account_token = null
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_deployment_v1" "variable" {
  spec {
    template {
      spec {
        automount_service_account_token = var.automount
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}
`
	evalCtx := &hcl.EvalContext{Variables: map[string]cty.Value{"var": cty.ObjectVal(map[string]cty.Value{"automount": cty.False})}}
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.Empty(t, errs)
	got := map[string]interface{}{}
	for _, m := range manifests {
		spec := podSpecAt(t, m, "spec", "template", "spec")
		got[m["metadata"].(map[string]interface{})["name"].(string)] = spec["automountServiceAccountToken"]
	}
	assert.Equal(t, false, got["off"], "an explicit false is kept")
	assert.Equal(t, true, got["on"])
	assert.Equal(t, true, got["null"], "null is unset to Terraform, so the provider default applies")
	assert.Equal(t, false, got["variable"], "a resolved variable is used as is")
}

func TestExtractTypedResourcesDoesNotGuessAnUnresolvedAutomount(t *testing.T) {
	src := `
resource "kubernetes_pod_v1" "web" {
  spec {
    automount_service_account_token = var.not_declared
    container {
      name  = "app"
      image = "nginx"
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Len(t, errs, 1, "the unresolved attribute is reported")
	require.Len(t, manifests, 1)
	assert.NotContains(t, podSpecAt(t, manifests[0], "spec"), "automountServiceAccountToken",
		"a value that could not be resolved is left out, not replaced by the default")
}

// automountRego mirrors the precedence the automount-service-account rule
// (C-0034) applies: the pod spec's automountServiceAccountToken wins, and only
// when it is absent does the ServiceAccount's own setting decide.
const automountRego = `
package test

import rego.v1

mounts if input.workload.spec.template.spec.automountServiceAccountToken == true

mounts if {
	not has_pod_setting
	not input.serviceAccount.automountServiceAccountToken == false
}

has_pod_setting if {
	_ = input.workload.spec.template.spec.automountServiceAccountToken
}
`

func TestTerraformDeploymentMountsTokenDespiteServiceAccountOptOut(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
resource "kubernetes_service_account_v1" "app" {
  metadata {
    name = "app"
  }
  automount_service_account_token = false
}

resource "kubernetes_deployment_v1" "app" {
  metadata {
    name = "app"
  }
  spec {
    template {
      spec {
        service_account_name = "app"
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}
`), 0o600))

	workloads, errs := NewTerraformDirectory(dir).GetWorkloads(dir)
	require.Empty(t, errs)
	input := map[string]interface{}{}
	for _, list := range workloads {
		for _, w := range list {
			switch w.GetKind() {
			case "ServiceAccount":
				input["serviceAccount"] = w.GetObject()
			case "Deployment":
				input["workload"] = w.GetObject()
			}
		}
	}
	require.Contains(t, input, "serviceAccount")
	require.Contains(t, input, "workload")

	raw, err := json.Marshal(input)
	require.NoError(t, err)
	var decoded interface{}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	rs, err := rego.New(rego.Query("data.test.mounts"), rego.Module("test.rego", automountRego), rego.Input(decoded)).Eval(context.Background())
	require.NoError(t, err)
	require.Len(t, rs, 1, "the provider sends automountServiceAccountToken: true, so the pod mounts a token whatever the ServiceAccount says")
	assert.Equal(t, true, rs[0].Expressions[0].Value)
}

func TestExtractTypedResourcesDoesNotApplyAutomountDefaultWhenTryHidesUnresolvableReference(t *testing.T) {
	src := `
resource "kubernetes_pod_v1" "unresolvable_try" {
  spec {
    automount_service_account_token = try(kubernetes_service_account_v1.ci.automount_service_account_token, null)
    container {
      name  = "app"
      image = "nginx"
    }
  }
}

resource "kubernetes_pod_v1" "resolvable_fallback" {
  spec {
    automount_service_account_token = try(var.missing_bool, false)
    container {
      name  = "app"
      image = "nginx"
    }
  }
}

resource "kubernetes_pod_v1" "resolvable_null" {
  spec {
    automount_service_account_token = try(var.declared_null, null)
    container {
      name  = "app"
      image = "nginx"
    }
  }
}
`
	evalCtx := &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var": cty.ObjectVal(map[string]cty.Value{
				"declared_null": cty.NullVal(cty.Bool),
			}),
		},
		Functions: terraformFunctions,
	}
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), evalCtx)
	require.Empty(t, errs, "try(...) suppresses diagnostics so no eval errors are returned")
	require.Len(t, manifests, 3)

	byName := map[string]map[string]interface{}{}
	for _, m := range manifests {
		byName[m["metadata"].(map[string]interface{})["name"].(string)] = m
	}

	assert.NotContains(t, podSpecAt(t, byName["unresolvable_try"], "spec"), "automountServiceAccountToken",
		"try(...) hiding an unresolvable reference must not apply provider default automountServiceAccountToken")

	assert.Equal(t, false, podSpecAt(t, byName["resolvable_fallback"], "spec")["automountServiceAccountToken"],
		"fallback value in try(...) must be preserved")

	assert.Equal(t, true, podSpecAt(t, byName["resolvable_null"], "spec")["automountServiceAccountToken"],
		"explicitly resolvable null in try(...) must take provider default")
}
