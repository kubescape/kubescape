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
	certificatesv1 "k8s.io/api/certificates/v1"
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
    pod_failure_policy {
      rule {
        action = "FailJob"
        on_pod_condition {
          type   = "DisruptionTarget"
          status = "True"
        }
      }
    }
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
      volume_device {
        name        = "raw-disk"
        device_path = "/dev/xvdba"
      }
    }
    dns_config {
      nameservers = ["1.1.1.1"]
      option {
        name  = "ndots"
        value = "1"
      }
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
    volume {
      name = "ephem"
      ephemeral {
        volume_claim_template {
          metadata {
            labels = { type = "my-type" }
          }
          spec {
            access_modes = ["ReadWriteOnce"]
          }
        }
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
	require.NotNil(t, job.Spec.PodFailurePolicy)
	require.Len(t, job.Spec.PodFailurePolicy.Rules, 1)
	assert.Equal(t, batchv1.PodFailurePolicyActionFailJob, job.Spec.PodFailurePolicy.Rules[0].Action)
	require.Len(t, job.Spec.PodFailurePolicy.Rules[0].OnPodConditions, 1)
	assert.Equal(t, corev1.PodConditionType("DisruptionTarget"), job.Spec.PodFailurePolicy.Rules[0].OnPodConditions[0].Type)
	assert.Equal(t, corev1.ConditionTrue, job.Spec.PodFailurePolicy.Rules[0].OnPodConditions[0].Status)

	cronJob := targets["CronJob"].(*batchv1.CronJob)
	require.NotNil(t, cronJob.Spec.JobTemplate.Spec.TTLSecondsAfterFinished)
	assert.Equal(t, int32(30), *cronJob.Spec.JobTemplate.Spec.TTLSecondsAfterFinished)

	pod := targets["Pod"].(*corev1.Pod)
	require.Len(t, pod.Spec.Containers[0].VolumeDevices, 1)
	assert.Equal(t, "raw-disk", pod.Spec.Containers[0].VolumeDevices[0].Name)
	assert.Equal(t, "/dev/xvdba", pod.Spec.Containers[0].VolumeDevices[0].DevicePath)

	require.NotNil(t, pod.Spec.DNSConfig)
	require.Len(t, pod.Spec.DNSConfig.Options, 1)
	assert.Equal(t, "ndots", pod.Spec.DNSConfig.Options[0].Name)
	require.NotNil(t, pod.Spec.DNSConfig.Options[0].Value)
	assert.Equal(t, "1", *pod.Spec.DNSConfig.Options[0].Value)

	require.Len(t, pod.Spec.Volumes, 3)
	secretVolume := pod.Spec.Volumes[0].Secret
	require.NotNil(t, secretVolume.DefaultMode)
	assert.Equal(t, int32(0o644), *secretVolume.DefaultMode)
	require.Len(t, secretVolume.Items, 2)
	require.NotNil(t, secretVolume.Items[0].Mode)
	assert.Equal(t, int32(0o400), *secretVolume.Items[0].Mode)
	assert.Nil(t, secretVolume.Items[1].Mode)
	require.NotNil(t, pod.Spec.Volumes[1].ConfigMap.DefaultMode)
	assert.Equal(t, int32(0o755), *pod.Spec.Volumes[1].ConfigMap.DefaultMode)

	ephemeralVolume := pod.Spec.Volumes[2].Ephemeral
	require.NotNil(t, ephemeralVolume)
	require.NotNil(t, ephemeralVolume.VolumeClaimTemplate)
	assert.Equal(t, "my-type", ephemeralVolume.VolumeClaimTemplate.Labels["type"])
	assert.Equal(t, []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, ephemeralVolume.VolumeClaimTemplate.Spec.AccessModes)
}

// A Secret's data attributes are renamed to the fields the provider sends
// them as, only on a Secret, and only at its top level: data and data_wo to
// stringData, binary_data and binary_data_wo to data. A Secret has no
// binaryData field, a ConfigMap does.
func TestAttributeKeyForSecretData(t *testing.T) {
	assert.Equal(t, "stringData", attributeKeyFor("kubernetes_secret_v1.s", "data"))
	assert.Equal(t, "stringData", attributeKeyFor("kubernetes_secret.s", "data"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_config_map_v1.cm", "data"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_secret_v1.s.metadata", "data"))
	assert.Equal(t, "stringData", attributeKeyFor("kubernetes_secret_v1.s", "data_wo"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_secret_v1.s", "binary_data"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_secret.s", "binary_data"))
	assert.Equal(t, "data", attributeKeyFor("kubernetes_secret_v1.s", "binary_data_wo"))
	assert.Equal(t, "binaryData", attributeKeyFor("kubernetes_config_map_v1.cm", "binary_data"))
}

// The values of a Secret's binary_data, data_wo and binary_data_wo end up in
// data and stringData, the fields the scan masks before it reports a Secret,
// and the Secret decodes into the Kubernetes type.
func TestExtractTypedResourcesSecretDataFields(t *testing.T) {
	byName := typedManifestsByName(t, `
resource "kubernetes_secret_v1" "binary" {
  metadata {
    name = "binary"
  }
  binary_data = {
    key = "aHVudGVyMw=="
  }
}

resource "kubernetes_secret_v1" "write_only" {
  metadata {
    name = "write-only"
  }
  data_wo = {
    password = "hunter2"
  }
  data_wo_revision = 1
  binary_data_wo = {
    key = "aHVudGVyNA=="
  }
  binary_data_wo_revision = 1
}
`)
	binary := byName["Secret/binary"]
	assert.Equal(t, map[string]interface{}{"key": "aHVudGVyMw=="}, binary["data"])
	writeOnly := byName["Secret/write-only"]
	assert.Equal(t, map[string]interface{}{"password": "hunter2"}, writeOnly["stringData"])
	assert.Equal(t, map[string]interface{}{"key": "aHVudGVyNA=="}, writeOnly["data"])
	for _, m := range []map[string]interface{}{binary, writeOnly} {
		data, err := json.Marshal(m)
		require.NoError(t, err)
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var secret corev1.Secret
		require.NoError(t, dec.Decode(&secret), "the Secret does not decode into the Kubernetes type")
	}
}

// The provider's control attributes and timeouts blocks tell the provider how
// to apply an object. They are not part of the Kubernetes object, so they are
// left out of the converted manifests.
func TestExtractTypedResourcesStripsProviderControlArguments(t *testing.T) {
	src := `
resource "kubernetes_deployment_v1" "d" {
  wait_for_rollout = true
  timeouts {
    create = "3m"
  }
  metadata {
    name = "d"
  }
  spec {
    selector {
      match_labels = { app = "a" }
    }
    template {
      metadata {
        labels = { app = "a" }
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

resource "kubernetes_service_v1" "s" {
  wait_for_load_balancer = false
  metadata {
    name = "s"
  }
  spec {
    type = "LoadBalancer"
    port {
      port = 80
    }
  }
}

resource "kubernetes_job_v1" "j" {
  wait_for_completion = true
  metadata {
    name = "j"
  }
  spec {
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

resource "kubernetes_namespace_v1" "ns" {
  wait_for_default_service_account = true
  metadata {
    name = "ns"
  }
}

resource "kubernetes_secret_v1" "tok" {
  wait_for_service_account_token = true
  metadata {
    name        = "tok"
    annotations = { "kubernetes.io/service-account.name" = "sa" }
  }
  type = "kubernetes.io/service-account-token"
}

resource "kubernetes_persistent_volume_claim_v1" "pvc" {
  wait_until_bound = false
  metadata {
    name = "pvc"
  }
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = { storage = "1Gi" }
    }
  }
}

resource "kubernetes_certificate_signing_request_v1" "csr" {
  auto_approve = true
  metadata {
    name = "csr"
  }
  spec {
    request     = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K"
    signer_name = "kubernetes.io/kube-apiserver-client"
  }
}

resource "kubernetes_pod_v1" "pod" {
  target_state = ["Running"]
  metadata {
    name = "pod"
  }
  spec {
    container {
      name  = "app"
      image = "nginx"
    }
  }
}

resource "kubernetes_secret_v1" "wo" {
  metadata {
    name = "wo"
  }
  data_wo                 = { password = "p" }
  data_wo_revision        = 1
  binary_data_wo          = { key = "aw==" }
  binary_data_wo_revision = 1
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Empty(t, errs)
	require.Len(t, manifests, 9)

	targets := map[string]interface{}{
		"Deployment":                &appsv1.Deployment{},
		"Service":                   &corev1.Service{},
		"Job":                       &batchv1.Job{},
		"Namespace":                 &corev1.Namespace{},
		"Secret":                    &corev1.Secret{},
		"PersistentVolumeClaim":     &corev1.PersistentVolumeClaim{},
		"CertificateSigningRequest": &certificatesv1.CertificateSigningRequest{},
		"Pod":                       &corev1.Pod{},
	}
	for _, m := range manifests {
		kind, _ := m["kind"].(string)
		for _, key := range []string{"timeouts", "waitForRollout", "waitForLoadBalancer", "waitForCompletion",
			"waitForDefaultServiceAccount", "waitForServiceAccountToken", "waitUntilBound",
			"autoApprove", "targetState", "dataWoRevision", "binaryDataWoRevision"} {
			assert.NotContains(t, m, key, "%s keeps the provider control argument %s", kind, key)
		}
		target, ok := targets[kind]
		require.True(t, ok, "unexpected kind %q", kind)
		data, err := json.Marshal(m)
		require.NoError(t, err)
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		require.NoError(t, dec.Decode(target), "%s does not decode into the Kubernetes type", kind)
	}
}

// A dynamic block may generate a provider control block such as timeouts,
// which is stripped without an error. A dynamic block still can't generate a
// Terraform meta-block such as lifecycle.
func TestExtractTypedResourcesDynamicControlBlocks(t *testing.T) {
	t.Run("dynamic timeouts is stripped", func(t *testing.T) {
		src := `
resource "kubernetes_namespace_v1" "ns" {
  dynamic "timeouts" {
    for_each = [1]
    content {
      create = "3m"
    }
  }
  metadata {
    name = "ns"
  }
}
`
		manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
		require.Empty(t, errs)
		require.Len(t, manifests, 1)
		assert.NotContains(t, manifests[0], "timeouts")
	})

	t.Run("dynamic lifecycle is an error", func(t *testing.T) {
		src := `
resource "kubernetes_namespace_v1" "ns" {
  dynamic "lifecycle" {
    for_each = [1]
    content {
      prevent_destroy = true
    }
  }
  metadata {
    name = "ns"
  }
}
`
		_, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
		require.Len(t, errs, 1)
		assert.ErrorContains(t, errs[0], `dynamic cannot generate Terraform meta-block "lifecycle"`)
	})
}
