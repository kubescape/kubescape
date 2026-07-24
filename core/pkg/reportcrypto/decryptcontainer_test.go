package reportcrypto

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func encryptedValue(t *testing.T, dek []byte, value string) string {
	t.Helper()

	encrypted, err := EncryptString(value, dek)
	require.NoError(t, err)
	return encrypted
}

func TestDecryptContainerMetadataUnstructured(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	enc := func(value string) string { return encryptedValue(t, dek, value) }
	resource := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"serviceAccountName": enc("workload-sa"),
					"serviceAccount":     enc("legacy-sa"),
					"imagePullSecrets": []any{
						map[string]any{"name": enc("registry-secret")},
						"malformed-entry",
					},
					"containers": []any{
						map[string]any{
							"name":  enc("api"),
							"image": enc("registry.example/api:v1"),
							"env": []any{
								map[string]any{"name": "TOKEN", "value": enc("secret-value")},
								map[string]any{"name": "SECRET_REF", "valueFrom": map[string]any{
									"secretKeyRef": map[string]any{"name": enc("app-secret"), "key": "token"},
								}},
								map[string]any{"name": "CONFIG_REF", "valueFrom": map[string]any{
									"configMapKeyRef": map[string]any{"name": enc("app-config"), "key": "url"},
								}},
								"malformed-entry",
							},
							"envFrom": []any{
								map[string]any{"secretRef": map[string]any{"name": enc("env-secret")}},
								map[string]any{"configMapRef": map[string]any{"name": enc("env-config")}},
							},
						},
					},
					"initContainers": []any{
						map[string]any{"name": enc("migrate"), "image": enc("registry.example/migrate:v1")},
					},
					"ephemeralContainers": []any{
						map[string]any{"name": enc("debugger"), "image": enc("busybox:1.36")},
					},
				},
			},
		},
	})

	require.NoError(t, DecryptContainerMetadata(resource, dek))

	podSpec := resource.GetObject()["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	assert.Equal(t, "workload-sa", podSpec["serviceAccountName"])
	assert.Equal(t, "legacy-sa", podSpec["serviceAccount"])
	assert.Equal(t, "registry-secret", podSpec["imagePullSecrets"].([]any)[0].(map[string]any)["name"])

	container := podSpec["containers"].([]any)[0].(map[string]any)
	assert.Equal(t, "api", container["name"])
	assert.Equal(t, "registry.example/api:v1", container["image"])
	env := container["env"].([]any)
	assert.Equal(t, "secret-value", env[0].(map[string]any)["value"])
	assert.Equal(t, "app-secret", env[1].(map[string]any)["valueFrom"].(map[string]any)["secretKeyRef"].(map[string]any)["name"])
	assert.Equal(t, "app-config", env[2].(map[string]any)["valueFrom"].(map[string]any)["configMapKeyRef"].(map[string]any)["name"])
	envFrom := container["envFrom"].([]any)
	assert.Equal(t, "env-secret", envFrom[0].(map[string]any)["secretRef"].(map[string]any)["name"])
	assert.Equal(t, "env-config", envFrom[1].(map[string]any)["configMapRef"].(map[string]any)["name"])
	assert.Equal(t, "migrate", podSpec["initContainers"].([]any)[0].(map[string]any)["name"])
	assert.Equal(t, "debugger", podSpec["ephemeralContainers"].([]any)[0].(map[string]any)["name"])
}

func TestDecryptContainerMetadataTyped(t *testing.T) {
	dek, err := GenerateDEK()
	require.NoError(t, err)

	enc := func(value string) string { return encryptedValue(t, dek, value) }
	podSpec := map[string]any{
		"containers": []corev1.Container{{
			Name:  enc("api"),
			Image: enc("api:v1"),
			Env: []corev1.EnvVar{
				{Name: "PASSWORD", Value: enc("hunter2")},
				{Name: "SECRET", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: enc("typed-secret")}}}},
				{Name: "CONFIG", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: enc("typed-config")}}}},
			},
			EnvFrom: []corev1.EnvFromSource{
				{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: enc("env-secret")}}},
				{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: enc("env-config")}}},
			},
		}},
		"ephemeralContainers": []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:  enc("debugger"),
				Image: enc("busybox:1.36"),
				Env:   []corev1.EnvVar{{Name: "TOKEN", Value: enc("debug-token")}},
			},
		}},
		"imagePullSecrets": []corev1.LocalObjectReference{{Name: enc("pull-secret")}},
	}
	resource := workloadinterface.NewWorkloadObj(map[string]any{"spec": podSpec})

	require.NoError(t, DecryptContainerMetadata(resource, dek))

	containers := podSpec["containers"].([]corev1.Container)
	assert.Equal(t, "api", containers[0].Name)
	assert.Equal(t, "api:v1", containers[0].Image)
	assert.Equal(t, "hunter2", containers[0].Env[0].Value)
	assert.Equal(t, "typed-secret", containers[0].Env[1].ValueFrom.SecretKeyRef.Name)
	assert.Equal(t, "typed-config", containers[0].Env[2].ValueFrom.ConfigMapKeyRef.Name)
	assert.Equal(t, "env-secret", containers[0].EnvFrom[0].SecretRef.Name)
	assert.Equal(t, "env-config", containers[0].EnvFrom[1].ConfigMapRef.Name)
	ephemeral := podSpec["ephemeralContainers"].([]corev1.EphemeralContainer)
	assert.Equal(t, "debugger", ephemeral[0].Name)
	assert.Equal(t, "debug-token", ephemeral[0].Env[0].Value)
	assert.Equal(t, "pull-secret", podSpec["imagePullSecrets"].([]corev1.LocalObjectReference)[0].Name)
}

func TestDecryptContainerMetadataHandlesNilPlaintextAndErrors(t *testing.T) {
	require.NoError(t, DecryptContainerMetadata(nil, make([]byte, 32)))

	resource := workloadinterface.NewWorkloadObj(nil)
	require.NoError(t, DecryptContainerMetadata(resource, make([]byte, 32)))

	resource = workloadinterface.NewWorkloadObj(map[string]any{
		"spec": map[string]any{
			"containers": []any{map[string]any{"name": "plaintext", "image": "nginx:latest"}},
		},
	})
	require.NoError(t, DecryptContainerMetadata(resource, make([]byte, 32)))

	resource = workloadinterface.NewWorkloadObj(map[string]any{
		"spec": map[string]any{
			"containers": []any{map[string]any{"name": "ENC[AES256_GCM,invalid]"}},
		},
	})
	err := DecryptContainerMetadata(resource, make([]byte, 32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ciphertext payload")
}
