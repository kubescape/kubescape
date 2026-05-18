package anonymizer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestAnonymizeContainerMetadata(t *testing.T) {
	tests := []struct {
		name     string
		object   map[string]interface{}
		validate func(t *testing.T, spec map[string]interface{})
	}{
		{
			name: "typed containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []corev1.Container{
						{
							Name:  "payment-api",
							Image: "nginx:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]corev1.Container)
				if !assert.True(t, ok, "expected typed containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				assert.NotEqual(t, "payment-api", containers[0].Name)
				assert.NotEqual(t, "nginx:latest", containers[0].Image)
				assert.Contains(t, containers[0].Name, "ctr-")
				assert.Contains(t, containers[0].Image, "img-")
			},
		},
		{
			name: "unstructured containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "payment-api",
							"image": "nginx:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]interface{})
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]interface{})
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				assert.NotEqual(t, "payment-api", container["name"])
				assert.NotEqual(t, "nginx:latest", container["image"])
				assert.Contains(t, container["name"], "ctr-")
				assert.Contains(t, container["image"], "img-")
			},
		},
		{
			name: "typed init containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"initContainers": []corev1.Container{
						{
							Name:  "init-db",
							Image: "postgres:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["initContainers"].([]corev1.Container)
				if !assert.True(t, ok, "expected typed init containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				assert.NotEqual(t, "init-db", containers[0].Name)
				assert.NotEqual(t, "postgres:latest", containers[0].Image)
				assert.Contains(t, containers[0].Name, "ctr-")
				assert.Contains(t, containers[0].Image, "img-")
			},
		},
		{
			name: "typed ephemeral containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"ephemeralContainers": []corev1.EphemeralContainer{
						{
							EphemeralContainerCommon: corev1.EphemeralContainerCommon{
								Name:  "debug-shell",
								Image: "busybox:latest",
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["ephemeralContainers"].([]corev1.EphemeralContainer)
				if !assert.True(t, ok, "expected typed ephemeral containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				assert.NotEqual(t, "debug-shell", containers[0].Name)
				assert.NotEqual(t, "busybox:latest", containers[0].Image)
				assert.Contains(t, containers[0].Name, "ctr-")
				assert.Contains(t, containers[0].Image, "img-")
			},
		},
		{
			name: "unstructured ephemeral containers should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"ephemeralContainers": []interface{}{
						map[string]interface{}{
							"name":  "debug-shell",
							"image": "busybox:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["ephemeralContainers"].([]interface{})
				if !assert.True(t, ok, "expected unstructured ephemeral containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]interface{})
				if !assert.True(t, ok, "expected unstructured ephemeral container map") {
					return
				}

				assert.NotEqual(t, "debug-shell", container["name"])
				assert.NotEqual(t, "busybox:latest", container["image"])
				assert.Contains(t, container["name"], "ctr-")
				assert.Contains(t, container["image"], "img-")
			},
		},
		{
			name: "typed container env references should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []corev1.Container{
						{
							Name:  "payment-api",
							Image: "nginx:latest",
							Env: []corev1.EnvVar{
								{
									Name: "SECRET_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "payment-secret",
											},
										},
									},
								},
								{
									Name: "CONFIG_PATH",
									ValueFrom: &corev1.EnvVarSource{
										ConfigMapKeyRef: &corev1.ConfigMapKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: "payment-config",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]corev1.Container)
				if !assert.True(t, ok, "expected typed containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				assert.NotEqual(t, "payment-secret", containers[0].Env[0].ValueFrom.SecretKeyRef.Name)
				assert.NotEqual(t, "payment-config", containers[0].Env[1].ValueFrom.ConfigMapKeyRef.Name)

				assert.Contains(t, containers[0].Env[0].ValueFrom.SecretKeyRef.Name, "ref-")
				assert.Contains(t, containers[0].Env[1].ValueFrom.ConfigMapKeyRef.Name, "ref-")
			},
		},
		{
			name: "unstructured container env references should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name":  "payment-api",
							"image": "nginx:latest",
							"env": []interface{}{
								map[string]interface{}{
									"name": "SECRET_TOKEN",
									"valueFrom": map[string]interface{}{
										"secretKeyRef": map[string]interface{}{
											"name": "payment-secret",
										},
									},
								},
								map[string]interface{}{
									"name": "CONFIG_PATH",
									"valueFrom": map[string]interface{}{
										"configMapKeyRef": map[string]interface{}{
											"name": "payment-config",
										},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]interface{})
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]interface{})
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				env, ok := container["env"].([]interface{})
				if !assert.True(t, ok, "expected env slice") {
					return
				}
				if !assert.Len(t, env, 2) {
					return
				}

				secretEnv, ok := env[0].(map[string]interface{})
				if !assert.True(t, ok, "expected secret env map") {
					return
				}

				configEnv, ok := env[1].(map[string]interface{})
				if !assert.True(t, ok, "expected config env map") {
					return
				}

				secretValueFrom, ok := secretEnv["valueFrom"].(map[string]interface{})
				if !assert.True(t, ok, "expected secret valueFrom map") {
					return
				}

				configValueFrom, ok := configEnv["valueFrom"].(map[string]interface{})
				if !assert.True(t, ok, "expected config valueFrom map") {
					return
				}

				secretRef, ok := secretValueFrom["secretKeyRef"].(map[string]interface{})
				if !assert.True(t, ok, "expected secretKeyRef map") {
					return
				}

				configRef, ok := configValueFrom["configMapKeyRef"].(map[string]interface{})
				if !assert.True(t, ok, "expected configMapKeyRef map") {
					return
				}

				assert.NotEqual(t, "payment-secret", secretRef["name"])
				assert.NotEqual(t, "payment-config", configRef["name"])
				assert.Contains(t, secretRef["name"], "ref-")
				assert.Contains(t, configRef["name"], "ref-")
			},
		},
		{
			name: "typed container envFrom references should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []corev1.Container{
						{
							Name: "payment-api",
							EnvFrom: []corev1.EnvFromSource{
								{
									SecretRef: &corev1.SecretEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "payment-secret",
										},
									},
								},
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "payment-config",
										},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]corev1.Container)
				if !assert.True(t, ok, "expected typed containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				assert.NotEqual(t, "payment-secret", containers[0].EnvFrom[0].SecretRef.Name)
				assert.NotEqual(t, "payment-config", containers[0].EnvFrom[1].ConfigMapRef.Name)
				assert.Contains(t, containers[0].EnvFrom[0].SecretRef.Name, "ref-")
				assert.Contains(t, containers[0].EnvFrom[1].ConfigMapRef.Name, "ref-")
			},
		},
		{
			name: "unstructured container envFrom references should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name": "payment-api",
							"envFrom": []interface{}{
								map[string]interface{}{
									"secretRef": map[string]interface{}{
										"name": "payment-secret",
									},
								},
								map[string]interface{}{
									"configMapRef": map[string]interface{}{
										"name": "payment-config",
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]interface{})
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]interface{})
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				envFrom, ok := container["envFrom"].([]interface{})
				if !assert.True(t, ok, "expected envFrom slice") {
					return
				}
				if !assert.Len(t, envFrom, 2) {
					return
				}

				secretEnvFrom, ok := envFrom[0].(map[string]interface{})
				if !assert.True(t, ok, "expected secret envFrom map") {
					return
				}

				configEnvFrom, ok := envFrom[1].(map[string]interface{})
				if !assert.True(t, ok, "expected config envFrom map") {
					return
				}

				secretRef, ok := secretEnvFrom["secretRef"].(map[string]interface{})
				if !assert.True(t, ok, "expected secretRef map") {
					return
				}

				configRef, ok := configEnvFrom["configMapRef"].(map[string]interface{})
				if !assert.True(t, ok, "expected configMapRef map") {
					return
				}

				assert.NotEqual(t, "payment-secret", secretRef["name"])
				assert.NotEqual(t, "payment-config", configRef["name"])
				assert.Contains(t, secretRef["name"], "ref-")
				assert.Contains(t, configRef["name"], "ref-")
			},
		},
		{
			name: "typed container literal env values should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []corev1.Container{
						{
							Name: "payment-api",
							Env: []corev1.EnvVar{
								{
									Name:  "DATABASE_URL",
									Value: "postgres://example-user@example-host.internal/prod",
								},
								{
									Name:  "CONNECTION_STRING",
									Value: "Server=db;User=demo;Password=masked;",
								},
								{
									Name:  "CONFIG",
									Value: "redis://:secret@redis.internal:6379",
								},
								{
									Name:  "LOG_LEVEL",
									Value: "info",
								},
								{
									Name:  "PORT",
									Value: "8080",
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]corev1.Container)
				if !assert.True(t, ok, "expected typed containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				assert.NotEqual(t, "postgres://example-user@example-host.internal/prod", containers[0].Env[0].Value)
				assert.NotEqual(t, "Server=db;User=demo;Password=masked;", containers[0].Env[1].Value)
				assert.NotEqual(t, "redis://:secret@redis.internal:6379", containers[0].Env[2].Value)

				assert.Contains(t, containers[0].Env[0].Value, "env-")
				assert.Contains(t, containers[0].Env[1].Value, "env-")
				assert.Contains(t, containers[0].Env[2].Value, "env-")

				assert.Equal(t, "info", containers[0].Env[3].Value)
				assert.Equal(t, "8080", containers[0].Env[4].Value)
			},
		},
		{
			name: "unstructured container literal env values should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name": "payment-api",
							"env": []interface{}{
								map[string]interface{}{
									"name":  "DATABASE_URL",
									"value": "postgres://example-user@example-host.internal/prod",
								},
								map[string]interface{}{
									"name":  "REDIS_URL",
									"value": "redis://:secret@redis.internal:6379",
								},
								map[string]interface{}{
									"name":  "CONFIG",
									"value": "mongodb://example-user@example-host.internal:27017/prod",
								},
								map[string]interface{}{
									"name":  "FEATURE_FLAG",
									"value": "true",
								},
								map[string]interface{}{
									"name":  "PORT",
									"value": "8080",
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				containers, ok := spec["containers"].([]interface{})
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]interface{})
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				env, ok := container["env"].([]interface{})
				if !assert.True(t, ok, "expected env slice") {
					return
				}
				if !assert.Len(t, env, 5) {
					return
				}

				firstEnv, ok := env[0].(map[string]interface{})
				if !assert.True(t, ok, "expected first env map") {
					return
				}

				secondEnv, ok := env[1].(map[string]interface{})
				if !assert.True(t, ok, "expected second env map") {
					return
				}

				thirdEnv, ok := env[2].(map[string]interface{})
				if !assert.True(t, ok, "expected third env map") {
					return
				}

				fourthEnv, ok := env[3].(map[string]interface{})
				if !assert.True(t, ok, "expected fourth env map") {
					return
				}

				fifthEnv, ok := env[4].(map[string]interface{})
				if !assert.True(t, ok, "expected fifth env map") {
					return
				}

				assert.NotEqual(t, "postgres://example-user@example-host.internal/prod", firstEnv["value"])
				assert.NotEqual(t, "redis://:secret@redis.internal:6379", secondEnv["value"])
				assert.NotEqual(t, "mongodb://example-user@example-host.internal:27017/prod", thirdEnv["value"])

				assert.Contains(t, firstEnv["value"], "env-")
				assert.Contains(t, secondEnv["value"], "env-")
				assert.Contains(t, thirdEnv["value"], "env-")

				assert.Equal(t, "true", fourthEnv["value"])
				assert.Equal(t, "8080", fifthEnv["value"])
			},
		},

		{
			name: "typed image pull secrets should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"imagePullSecrets": []corev1.LocalObjectReference{
						{
							Name: "corp-registry-creds",
						},
					},
				},
			},

			validate: func(t *testing.T, spec map[string]interface{}) {
				refs, ok := spec["imagePullSecrets"].([]corev1.LocalObjectReference)
				if !assert.True(t, ok, "expected typed image pull secrets") {
					return
				}
				if !assert.Len(t, refs, 1) {
					return
				}

				assert.NotEqual(t, "corp-registry-creds", refs[0].Name)
				assert.Contains(t, refs[0].Name, "ref-")
			},
		},

		{
			name: "unstructured image pull secrets should be anonymized",
			object: map[string]interface{}{
				"spec": map[string]interface{}{
					"imagePullSecrets": []interface{}{
						map[string]interface{}{
							"name": "corp-registry-creds",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]interface{}) {
				refs, ok := spec["imagePullSecrets"].([]interface{})
				if !assert.True(t, ok, "expected unstructured image pull secrets") {
					return
				}
				if !assert.Len(t, refs, 1) {
					return
				}

				ref, ok := refs[0].(map[string]interface{})
				if !assert.True(t, ok, "expected image pull secret map") {
					return
				}

				assert.NotEqual(t, "corp-registry-creds", ref["name"])
				assert.Contains(t, ref["name"], "ref-")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapping := NewMapping()
			resource := workloadinterface.NewWorkloadObj(test.object)

			anonymizeContainerMetadata(resource, mapping)

			spec, ok := resource.GetObject()["spec"].(map[string]interface{})
			assert.True(t, ok, "expected spec to be a map[string]interface{}")

			test.validate(t, spec)
		})
	}
}

func TestAnonymizeContainerMetadata_NilResource(t *testing.T) {
	assert.NotPanics(t, func() {
		anonymizeContainerMetadata(nil, NewMapping())
	})
}

func TestAnonymizeContainerList_MissingKey(t *testing.T) {
	obj := map[string]interface{}{}
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeContainerList(obj, "containers", mapping)
	})
}

func TestAnonymizeContainerList_NilValue(t *testing.T) {
	obj := map[string]interface{}{
		"containers": nil,
	}
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeContainerList(obj, "containers", mapping)
	})
}

func TestAnonymizeContainerList_InvalidType(t *testing.T) {
	obj := map[string]interface{}{
		"containers": "invalid",
	}
	mapping := NewMapping()

	assert.NotPanics(t, func() {
		anonymizeContainerList(obj, "containers", mapping)
	})
}

func TestIsSensitiveEnvKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"password key", "DB_PASSWORD", true},
		{"secret key", "MY_SECRET", true},
		{"token key", "API_TOKEN", true},
		{"access key", "ACCESS_KEY", true},
		{"credential key", "CREDENTIAL_VALUE", true},
		{"auth key", "AUTH_HEADER", true},
		{"cert key", "TLS_CERT", true},
		{"non sensitive app name", "APP_NAME", false},
		{"non sensitive port", "PORT", false},
		{"non sensitive env", "NODE_ENV", false},
		{"case insensitive", "db_password", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSensitiveEnvKey(tt.key))
		})
	}
}

func TestAnonymizeEnvVars_SensitiveValuesRedacted(t *testing.T) {
	mapping := NewMapping()
	container := map[string]interface{}{
		"name": "app",
		"env": []interface{}{
			map[string]interface{}{"name": "DB_PASSWORD", "value": "supersecret"},
			map[string]interface{}{"name": "API_TOKEN", "value": "tok-abc123"},
			map[string]interface{}{"name": "APP_NAME", "value": "myapp"},
		},
	}

	anonymizeEnvVars(container, mapping)

	envs := container["env"].([]interface{})
	for _, item := range envs {
		env := item.(map[string]interface{})
		name := env["name"].(string)
		val, _ := env["value"].(string)
		switch name {
		case "DB_PASSWORD":
			assert.NotEqual(t, "supersecret", val, "password must be anonymized")
			assert.NotEmpty(t, val)
		case "API_TOKEN":
			assert.NotEqual(t, "tok-abc123", val, "token must be anonymized")
			assert.NotEmpty(t, val)
		case "APP_NAME":
			assert.Equal(t, "myapp", val, "non-sensitive value must be preserved")
		}
	}
}

func TestAnonymizeEnvVars_NilEnv(t *testing.T) {
	mapping := NewMapping()
	container := map[string]interface{}{"name": "app", "env": nil}
	// must not panic
	anonymizeEnvVars(container, mapping)
}

func TestAnonymizeEnvVars_NoEnvKey(t *testing.T) {
	mapping := NewMapping()
	container := map[string]interface{}{"name": "app"}
	// must not panic
	anonymizeEnvVars(container, mapping)
}

func TestAnonymizeEnvVars_SameValueSameMappedToken(t *testing.T) {
	mapping := NewMapping()
	container := map[string]interface{}{
		"env": []interface{}{
			map[string]interface{}{"name": "DB_PASSWORD", "value": "same-secret"},
			map[string]interface{}{"name": "API_TOKEN", "value": "same-secret"},
		},
	}
	anonymizeEnvVars(container, mapping)
	envs := container["env"].([]interface{})
	val1 := envs[0].(map[string]interface{})["value"].(string)
	val2 := envs[1].(map[string]interface{})["value"].(string)
	assert.Equal(t, val1, val2, "same input value must produce same anonymized token")
}

func TestAnonymizeContainerList_TypedContainerEnvRedacted(t *testing.T) {
	mapping := NewMapping()
	obj := map[string]interface{}{}
	containers := []corev1.Container{
		{
			Name:  "app",
			Image: "nginx:latest",
			Env: []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: "supersecret"},
				{Name: "APP_NAME", Value: "myapp"},
			},
		},
	}
	obj["containers"] = containers
	anonymizeContainerList(obj, "containers", mapping)
	result := obj["containers"].([]corev1.Container)
	assert.NotEqual(t, "supersecret", result[0].Env[0].Value, "sensitive env value must be anonymized")
	assert.Equal(t, "myapp", result[0].Env[1].Value, "non-sensitive env value must be preserved")
}

func TestAnonymizeEphemeralContainerList_TypedEnvRedacted(t *testing.T) {
	mapping := NewMapping()
	obj := map[string]interface{}{}
	containers := []corev1.EphemeralContainer{
		{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name:  "debug",
				Image: "busybox",
				Env: []corev1.EnvVar{
					{Name: "API_TOKEN", Value: "tok-secret"},
					{Name: "PORT", Value: "8080"},
				},
			},
		},
	}
	obj["ephemeralContainers"] = containers
	anonymizeEphemeralContainerList(obj, "ephemeralContainers", mapping)
	result := obj["ephemeralContainers"].([]corev1.EphemeralContainer)
	assert.NotEqual(t, "tok-secret", result[0].Env[0].Value, "sensitive env value must be anonymized")
	assert.Equal(t, "8080", result[0].Env[1].Value, "non-sensitive env value must be preserved")
}
