package cautils

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// Fields the provider renames, or declares as strings and parses, convert to
// their Kubernetes name and type, so the converted objects decode into the
// Kubernetes types.
func TestExtractTypedResourcesProviderFieldTypes(t *testing.T) {
	src := `
resource "kubernetes_daemon_set_v1" "ds" {
  metadata {
    name = "ds"
  }
  spec {
    selector {
      match_labels = { app = "d" }
    }
    strategy {
      type = "RollingUpdate"
      rolling_update {
        max_unavailable = "1"
      }
    }
    template {
      metadata {
        labels = { app = "d" }
      }
      spec {
        container {
          name  = "app"
          image = "nginx"
        }
      }
    }
  }
}

resource "kubernetes_secret_v1" "s" {
  metadata {
    name = "s"
  }
  data = { "app.conf" = "log_level = debug" }
}

resource "kubernetes_job_v1" "j" {
  metadata {
    name = "j"
  }
  spec {
    ttl_seconds_after_finished = "10"
    template {
      metadata {}
      spec {
        restart_policy = "Never"
        container {
          name  = "app"
          image = "busybox"
        }
      }
    }
  }
}

resource "kubernetes_cron_job_v1" "cj" {
  metadata {
    name = "cj"
  }
  spec {
    schedule = "* * * * *"
    job_template {
      metadata {}
      spec {
        ttl_seconds_after_finished = "30"
        template {
          metadata {}
          spec {
            container {
              name  = "app"
              image = "busybox"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_pod_v1" "p" {
  metadata {
    name = "p"
  }
  spec {
    container {
      name  = "app"
      image = "nginx"
    }
    volume {
      name = "sec"
      secret {
        secret_name  = "s"
        default_mode = "0644"
        items {
          key  = "k"
          path = "p"
          mode = "0400"
        }
        items {
          key  = "k2"
          path = "p2"
        }
      }
    }
    volume {
      name = "cm"
      config_map {
        name         = "c"
        default_mode = "0755"
      }
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Empty(t, errs)
	require.Len(t, manifests, 5)

	targets := map[string]interface{}{
		"DaemonSet": &appsv1.DaemonSet{},
		"Secret":    &corev1.Secret{},
		"Job":       &batchv1.Job{},
		"CronJob":   &batchv1.CronJob{},
		"Pod":       &corev1.Pod{},
	}
	for _, m := range manifests {
		kind, _ := m["kind"].(string)
		target, ok := targets[kind]
		require.True(t, ok, "unexpected kind %q", kind)
		data, err := json.Marshal(m)
		require.NoError(t, err)
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		require.NoError(t, dec.Decode(target), "%s does not decode into the Kubernetes type", kind)
	}

	daemonSet := targets["DaemonSet"].(*appsv1.DaemonSet)
	assert.Equal(t, appsv1.RollingUpdateDaemonSetStrategyType, daemonSet.Spec.UpdateStrategy.Type)
	require.NotNil(t, daemonSet.Spec.UpdateStrategy.RollingUpdate)
	assert.Equal(t, "1", daemonSet.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable.String())

	secret := targets["Secret"].(*corev1.Secret)
	assert.Equal(t, map[string]string{"app.conf": "log_level = debug"}, secret.StringData)
	assert.Empty(t, secret.Data)

	job := targets["Job"].(*batchv1.Job)
	require.NotNil(t, job.Spec.TTLSecondsAfterFinished)
	assert.Equal(t, int32(10), *job.Spec.TTLSecondsAfterFinished)

	cronJob := targets["CronJob"].(*batchv1.CronJob)
	require.NotNil(t, cronJob.Spec.JobTemplate.Spec.TTLSecondsAfterFinished)
	assert.Equal(t, int32(30), *cronJob.Spec.JobTemplate.Spec.TTLSecondsAfterFinished)

	pod := targets["Pod"].(*corev1.Pod)
	require.Len(t, pod.Spec.Volumes, 2)
	secretVolume := pod.Spec.Volumes[0].Secret
	require.NotNil(t, secretVolume.DefaultMode)
	assert.Equal(t, int32(0o644), *secretVolume.DefaultMode)
	require.Len(t, secretVolume.Items, 2)
	require.NotNil(t, secretVolume.Items[0].Mode)
	assert.Equal(t, int32(0o400), *secretVolume.Items[0].Mode)
	assert.Nil(t, secretVolume.Items[1].Mode)
	require.NotNil(t, pod.Spec.Volumes[1].ConfigMap.DefaultMode)
	assert.Equal(t, int32(0o755), *pod.Spec.Volumes[1].ConfigMap.DefaultMode)
}

// A data attribute is renamed only on a Secret, and only at its top level.
func TestAttributeKeyForSecretData(t *testing.T) {
	assert.Equal(t, "stringData", attributeKeyFor("kubernetes_secret_v1.s", "data"))
	assert.Equal(t, "stringData", attributeKeyFor("kubernetes_secret.s", "data"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_config_map_v1.cm", "data"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_secret_v1.s.metadata", "data"))
}
