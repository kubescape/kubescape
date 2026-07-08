package anonymizer

import (
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestTransformContainerMetadata(t *testing.T) {
	tests := []struct {
		name     string
		object   map[string]any
		validate func(t *testing.T, spec map[string]any)
	}{
		{
			name: "typed containers should be anonymized",
			object: map[string]any{
				"spec": map[string]any{
					"containers": []corev1.Container{
						{
							Name:  "payment-api",
							Image: "nginx:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
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
			object: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "payment-api",
							"image": "nginx:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				containers, ok := spec["containers"].([]any)
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]any)
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
			object: map[string]any{
				"spec": map[string]any{
					"initContainers": []corev1.Container{
						{
							Name:  "init-db",
							Image: "postgres:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
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
			object: map[string]any{
				"spec": map[string]any{
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
			validate: func(t *testing.T, spec map[string]any) {
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
			object: map[string]any{
				"spec": map[string]any{
					"ephemeralContainers": []any{
						map[string]any{
							"name":  "debug-shell",
							"image": "busybox:latest",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				containers, ok := spec["ephemeralContainers"].([]any)
				if !assert.True(t, ok, "expected unstructured ephemeral containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]any)
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
			object: map[string]any{
				"spec": map[string]any{
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
			validate: func(t *testing.T, spec map[string]any) {
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
			object: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  "payment-api",
							"image": "nginx:latest",
							"env": []any{
								map[string]any{
									"name": "SECRET_TOKEN",
									"valueFrom": map[string]any{
										"secretKeyRef": map[string]any{
											"name": "payment-secret",
										},
									},
								},
								map[string]any{
									"name": "CONFIG_PATH",
									"valueFrom": map[string]any{
										"configMapKeyRef": map[string]any{
											"name": "payment-config",
										},
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				containers, ok := spec["containers"].([]any)
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]any)
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				env, ok := container["env"].([]any)
				if !assert.True(t, ok, "expected env slice") {
					return
				}
				if !assert.Len(t, env, 2) {
					return
				}

				secretEnv, ok := env[0].(map[string]any)
				if !assert.True(t, ok, "expected secret env map") {
					return
				}

				configEnv, ok := env[1].(map[string]any)
				if !assert.True(t, ok, "expected config env map") {
					return
				}

				secretValueFrom, ok := secretEnv["valueFrom"].(map[string]any)
				if !assert.True(t, ok, "expected secret valueFrom map") {
					return
				}

				configValueFrom, ok := configEnv["valueFrom"].(map[string]any)
				if !assert.True(t, ok, "expected config valueFrom map") {
					return
				}

				secretRef, ok := secretValueFrom["secretKeyRef"].(map[string]any)
				if !assert.True(t, ok, "expected secretKeyRef map") {
					return
				}

				configRef, ok := configValueFrom["configMapKeyRef"].(map[string]any)
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
			object: map[string]any{
				"spec": map[string]any{
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
			validate: func(t *testing.T, spec map[string]any) {
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
			object: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "payment-api",
							"envFrom": []any{
								map[string]any{
									"secretRef": map[string]any{
										"name": "payment-secret",
									},
								},
								map[string]any{
									"configMapRef": map[string]any{
										"name": "payment-config",
									},
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				containers, ok := spec["containers"].([]any)
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]any)
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				envFrom, ok := container["envFrom"].([]any)
				if !assert.True(t, ok, "expected envFrom slice") {
					return
				}
				if !assert.Len(t, envFrom, 2) {
					return
				}

				secretEnvFrom, ok := envFrom[0].(map[string]any)
				if !assert.True(t, ok, "expected secret envFrom map") {
					return
				}

				configEnvFrom, ok := envFrom[1].(map[string]any)
				if !assert.True(t, ok, "expected config envFrom map") {
					return
				}

				secretRef, ok := secretEnvFrom["secretRef"].(map[string]any)
				if !assert.True(t, ok, "expected secretRef map") {
					return
				}

				configRef, ok := configEnvFrom["configMapRef"].(map[string]any)
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
			object: map[string]any{
				"spec": map[string]any{
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
			validate: func(t *testing.T, spec map[string]any) {
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
			object: map[string]any{
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name": "payment-api",
							"env": []any{
								map[string]any{
									"name":  "DATABASE_URL",
									"value": "postgres://example-user@example-host.internal/prod",
								},
								map[string]any{
									"name":  "REDIS_URL",
									"value": "redis://:secret@redis.internal:6379",
								},
								map[string]any{
									"name":  "CONFIG",
									"value": "mongodb://example-user@example-host.internal:27017/prod",
								},
								map[string]any{
									"name":  "FEATURE_FLAG",
									"value": "true",
								},
								map[string]any{
									"name":  "PORT",
									"value": "8080",
								},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				containers, ok := spec["containers"].([]any)
				if !assert.True(t, ok, "expected unstructured containers") {
					return
				}
				if !assert.Len(t, containers, 1) {
					return
				}

				container, ok := containers[0].(map[string]any)
				if !assert.True(t, ok, "expected unstructured container map") {
					return
				}

				env, ok := container["env"].([]any)
				if !assert.True(t, ok, "expected env slice") {
					return
				}
				if !assert.Len(t, env, 5) {
					return
				}

				firstEnv, ok := env[0].(map[string]any)
				if !assert.True(t, ok, "expected first env map") {
					return
				}

				secondEnv, ok := env[1].(map[string]any)
				if !assert.True(t, ok, "expected second env map") {
					return
				}

				thirdEnv, ok := env[2].(map[string]any)
				if !assert.True(t, ok, "expected third env map") {
					return
				}

				fourthEnv, ok := env[3].(map[string]any)
				if !assert.True(t, ok, "expected fourth env map") {
					return
				}

				fifthEnv, ok := env[4].(map[string]any)
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
			object: map[string]any{
				"spec": map[string]any{
					"imagePullSecrets": []corev1.LocalObjectReference{
						{
							Name: "corp-registry-creds",
						},
					},
				},
			},

			validate: func(t *testing.T, spec map[string]any) {
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
			name: "typed service account name should be anonymized",
			object: map[string]any{
				"spec": map[string]any{
					"serviceAccountName": "payments-runtime",
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				serviceAccountName, ok := spec["serviceAccountName"].(string)
				if !assert.True(t, ok, "expected serviceAccountName string") {
					return
				}

				assert.NotEqual(t, "payments-runtime", serviceAccountName)
				assert.Contains(t, serviceAccountName, "sa-")
			},
		},
		{
			name: "deprecated service account should be anonymized",
			object: map[string]any{
				"spec": map[string]any{
					"serviceAccount": "payments-runtime",
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				serviceAccount, ok := spec["serviceAccount"].(string)
				if !assert.True(t, ok, "expected serviceAccount string") {
					return
				}

				assert.NotEqual(t, "payments-runtime", serviceAccount)
				assert.Contains(t, serviceAccount, "sa-")
			},
		},
		{
			name: "nested template deprecated service account should be anonymized",
			object: map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"serviceAccount": "analytics-runtime",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				template, ok := spec["template"].(map[string]any)
				if !assert.True(t, ok, "expected template map") {
					return
				}

				templateSpec, ok := template["spec"].(map[string]any)
				if !assert.True(t, ok, "expected template spec map") {
					return
				}

				serviceAccount, ok := templateSpec["serviceAccount"].(string)
				if !assert.True(t, ok, "expected serviceAccount string") {
					return
				}

				assert.NotEqual(t, "analytics-runtime", serviceAccount)
				assert.Contains(t, serviceAccount, "sa-")
			},
		},
		{
			name: "nested template service account name should be anonymized",
			object: map[string]any{
				"spec": map[string]any{
					"template": map[string]any{
						"spec": map[string]any{
							"serviceAccountName": "analytics-runtime",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				template, ok := spec["template"].(map[string]any)
				if !assert.True(t, ok, "expected template map") {
					return
				}

				templateSpec, ok := template["spec"].(map[string]any)
				if !assert.True(t, ok, "expected template spec map") {
					return
				}

				serviceAccountName, ok := templateSpec["serviceAccountName"].(string)
				if !assert.True(t, ok, "expected serviceAccountName string") {
					return
				}

				assert.NotEqual(t, "analytics-runtime", serviceAccountName)
				assert.Contains(t, serviceAccountName, "sa-")
			},
		},

		{
			name: "unstructured image pull secrets should be anonymized",
			object: map[string]any{
				"spec": map[string]any{
					"imagePullSecrets": []any{
						map[string]any{
							"name": "corp-registry-creds",
						},
					},
				},
			},
			validate: func(t *testing.T, spec map[string]any) {
				refs, ok := spec["imagePullSecrets"].([]any)
				if !assert.True(t, ok, "expected unstructured image pull secrets") {
					return
				}
				if !assert.Len(t, refs, 1) {
					return
				}

				ref, ok := refs[0].(map[string]any)
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
			transformer := NewMappingTransformer()
			resource := workloadinterface.NewWorkloadObj(test.object)

			assert.NoError(t, transformContainerMetadata(resource, transformer))

			spec, ok := resource.GetObject()["spec"].(map[string]any)
			assert.True(t, ok, "expected spec to be a map[string]any")

			test.validate(t, spec)
		})
	}
}

func TestTransformContainerMetadata_NilResource(t *testing.T) {
	assert.NoError(t, transformContainerMetadata(nil, NewMappingTransformer()))
}

func TestTransformContainerList_MissingKey(t *testing.T) {
	obj := map[string]any{}

	assert.NoError(t, transformContainerList(obj, "containers", NewMappingTransformer()))
}

func TestTransformContainerList_NilValue(t *testing.T) {
	obj := map[string]any{"containers": nil}

	assert.NoError(t, transformContainerList(obj, "containers", NewMappingTransformer()))
}

func TestTransformContainerList_InvalidType(t *testing.T) {
	obj := map[string]any{
		"containers": "invalid",
	}

	assert.NoError(t, transformContainerList(obj, "containers", NewMappingTransformer()))
}

func TestIsSensitiveEnvName_SeparatorlessVariants(t *testing.T) {
	cases := map[string]bool{
		"API_KEY":          true,
		"APIKEY":           true,
		"ACCESS_KEY":       true,
		"ACCESSKEY":        true,
		"PRIVATEKEY":       true,
		"PRIVATE_KEY":      true,
		"SECRETKEY":        true,
		"AUTHTOKEN":        true,
		"AUTH_TOKEN":       true,
		"app.api-key":      true,
		"CREDENTIAL":       true,
		"DATABASE_URL":     true,
		"DATABASEURL":      true,
		"CONNECTIONSTRING": true,
		"NORMAL_ENV":       false,
		"PORT":             false,
		"LOG_LEVEL":        false,
	}

	for name, want := range cases {
		if got := isSensitiveEnvName(name); got != want {
			t.Errorf("isSensitiveEnvName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestTransformUnstructuredEnv_LeaksAPIKeyValue(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE" //nolint:gosec

	container := map[string]any{
		"env": []any{
			map[string]any{
				"name":  "APIKEY",
				"value": secret,
			},
		},
	}

	assert.NoError(t, transformUnstructuredEnv(container, NewMappingTransformer()))

	got := container["env"].([]any)[0].(map[string]any)["value"].(string)
	if got == secret {
		t.Fatalf("env var APIKEY value was not transformed; secret leaked into output")
	}
}
