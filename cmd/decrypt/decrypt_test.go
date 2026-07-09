package decrypt

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/kubescape/kubescape/v3/core/pkg/reportcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptCommand(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "preserves unknown fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dek, err := reportcrypto.GenerateDEK()
			require.NoError(t, err)

			masterKey := []byte(
				"12345678901234567890123456789012",
			)

			encryptedRepo, err :=
				reportcrypto.EncryptString(
					"kubescape",
					dek,
				)
			require.NoError(t, err)

			encryptedPath, err :=
				reportcrypto.EncryptString(
					"/workspace/manifests/nginx/deployment.yaml",
					dek,
				)
			require.NoError(t, err)

			encryptedRelativePath, err :=
				reportcrypto.EncryptString(
					"manifests/nginx/deployment.yaml",
					dek,
				)
			require.NoError(t, err)

			encryptedName, err :=
				reportcrypto.EncryptString(
					"nginx-deployment",
					dek,
				)
			require.NoError(t, err)

			encryptedNamespace, err :=
				reportcrypto.EncryptString(
					"production",
					dek,
				)
			require.NoError(t, err)

			encryptedContainerName, err :=
				reportcrypto.EncryptString(
					"api",
					dek,
				)
			require.NoError(t, err)

			encryptedImage, err :=
				reportcrypto.EncryptString(
					"nginx:latest",
					dek,
				)
			require.NoError(t, err)

			encryptedEnvValue, err :=
				reportcrypto.EncryptString(
					"postgres://user:s3cret@db:5432/app",
					dek,
				)
			require.NoError(t, err)
			encryptedSecretRef, err :=
				reportcrypto.EncryptString(
					"payment-secret",
					dek,
				)
			require.NoError(t, err)

			encryptedConfigMapRef, err :=
				reportcrypto.EncryptString(
					"payment-config",
					dek,
				)
			require.NoError(t, err)

			encryptedEnvFromSecret, err :=
				reportcrypto.EncryptString(
					"application-secret",
					dek,
				)
			require.NoError(t, err)

			encryptedEnvFromConfigMap, err :=
				reportcrypto.EncryptString(
					"application-config",
					dek,
				)
			require.NoError(t, err)

			encryptedImagePullSecret, err :=
				reportcrypto.EncryptString(
					"registry-secret",
					dek,
				)
			require.NoError(t, err)

			encryptedServiceAccount, err :=
				reportcrypto.EncryptString(
					"payment-service-account",
					dek,
				)
			require.NoError(t, err)

			wrappedDEK, err :=
				reportcrypto.WrapDEK(
					dek,
					masterKey,
				)
			require.NoError(t, err)

			report := map[string]any{
				"resourceLabels": map[string]any{
					"team": "platform",
				},
				"scanCoverage": map[string]any{
					"all": true,
				},
				"resources": []map[string]any{
					{
						"resourceID":  "resource-1",
						"customField": "must-survive",
						"object": map[string]any{
							"apiVersion": "apps/v1",
							"kind":       "Deployment",
							"metadata": map[string]any{
								"name":      encryptedName,
								"namespace": encryptedNamespace,
							},
							"spec": map[string]any{
								"serviceAccountName": encryptedServiceAccount,
								"imagePullSecrets": []any{
									map[string]any{
										"name": encryptedImagePullSecret,
									},
								},
								"containers": []any{
									map[string]any{
										"name":  encryptedContainerName,
										"image": encryptedImage,
										"env": []any{
											map[string]any{
												"name":  "DATABASE_CONN",
												"value": encryptedEnvValue,
											},
											map[string]any{
												"name": "SECRET_TOKEN",
												"valueFrom": map[string]any{
													"secretKeyRef": map[string]any{
														"name": encryptedSecretRef,
													},
												},
											},
											map[string]any{
												"name": "CONFIG_PATH",
												"valueFrom": map[string]any{
													"configMapKeyRef": map[string]any{
														"name": encryptedConfigMapRef,
													},
												},
											},
										},
										"envFrom": []any{
											map[string]any{
												"secretRef": map[string]any{
													"name": encryptedEnvFromSecret,
												},
											},
											map[string]any{
												"configMapRef": map[string]any{
													"name": encryptedEnvFromConfigMap,
												},
											},
										},
									},
								},
							},
						},
						"source": map[string]any{
							"path":         encryptedPath,
							"relativePath": encryptedRelativePath,
						},
					},
				},
				"results": []map[string]any{
					{
						"resourceID": "resource-1",
						"prioritizedResource": map[string]any{
							"resourceID": "resource-1",
						},
						"controls": []map[string]any{
							{
								"rules": []map[string]any{
									{
										"paths": []map[string]any{
											{
												"resourceID": "resource-1",
											},
										},
										"relatedResourcesIDs": []string{
											"resource-1",
										},
									},
								},
							},
						},
					},
				},
				"metadata": map[string]any{
					"targetMetadata": map[string]any{
						"gitRepoContextMetadata": map[string]any{
							"repo": encryptedRepo,
						},
					},
					"encryptionMetadata": map[string]any{
						"encryptedDEK": wrappedDEK,
					},
				},
			}

			data, err := json.Marshal(report)
			require.NoError(t, err)

			tmp, err := os.CreateTemp(
				"",
				"encrypted-*.json",
			)
			require.NoError(t, err)

			defer os.Remove(tmp.Name())

			_, err = tmp.Write(data)
			require.NoError(t, err)

			require.NoError(t, tmp.Close())

			t.Setenv(
				"KUBESCAPE_MASTER_KEY",
				string(masterKey),
			)

			oldStdout := os.Stdout

			r, w, err := os.Pipe()
			require.NoError(t, err)

			os.Stdout = w

			defer func() {
				os.Stdout = oldStdout
			}()

			defer func() {
				_ = w.Close()
			}()

			cmd := GetDecryptCommand()

			err = cmd.RunE(
				cmd,
				[]string{tmp.Name()},
			)

			require.NoError(t, err)

			require.NoError(t, w.Close())

			var buf bytes.Buffer

			_, err = buf.ReadFrom(r)
			require.NoError(t, err)

			var output map[string]any

			err = json.Unmarshal(
				buf.Bytes(),
				&output,
			)
			require.NoError(t, err)

			assert.Contains(t, output, "resourceLabels")

			assert.Contains(t, output, "scanCoverage")

			metadata, ok :=
				output["metadata"].(map[string]any)
			require.True(t, ok, "metadata should be an object")

			targetMetadata, ok :=
				metadata["targetMetadata"].(map[string]any)
			require.True(t, ok, "targetMetadata should be an object")

			repoMetadata, ok :=
				targetMetadata["gitRepoContextMetadata"].(map[string]any)
			require.True(t, ok, "gitRepoContextMetadata should be an object")

			assert.Equal(t, "kubescape", repoMetadata["repo"])

			resources, ok := output["resources"].([]any)
			require.True(t, ok, "resources should be an array")

			require.Len(t, resources, 1)

			resource, ok := resources[0].(map[string]any)
			require.True(t, ok, "resource should be an object")

			resourceID, ok := resource["resourceID"].(string)
			require.True(t, ok, "resourceID should be a string")

			assert.Equal(t, "apps/v1/production/Deployment/nginx-deployment", resourceID)

			assert.Equal(t, "must-survive", resource["customField"])
			results, ok := output["results"].([]any)
			require.True(t, ok, "results should be an array")

			require.Len(t, results, 1)

			result, ok := results[0].(map[string]any)
			require.True(t, ok, "result should be an object")
			assert.Equal(t, resourceID, result["resourceID"])

			prioritized, ok := result["prioritizedResource"].(map[string]any)
			require.True(t, ok, "prioritizedResource should be an object")
			assert.Equal(t, resourceID, prioritized["resourceID"])

			controls, ok := result["controls"].([]any)
			require.True(t, ok, "controls should be an array")
			require.Len(t, controls, 1)

			control, ok := controls[0].(map[string]any)
			require.True(t, ok, "control should be an object")

			rules, ok := control["rules"].([]any)
			require.True(t, ok, "rules should be an array")

			require.Len(t, rules, 1)

			object, ok := resource["object"].(map[string]any)
			require.True(t, ok, "object should be an object")

			metadataObj, ok := object["metadata"].(map[string]any)
			require.True(t, ok, "metadata should be an object")

			assert.Equal(t, "nginx-deployment", metadataObj["name"])
			assert.Equal(t, "production", metadataObj["namespace"])

			spec, ok := object["spec"].(map[string]any)
			require.True(t, ok)

			assert.Equal(t, "payment-service-account", spec["serviceAccountName"])

			pullSecrets := spec["imagePullSecrets"].([]any)
			require.Len(t, pullSecrets, 1)

			pullSecret := pullSecrets[0].(map[string]any)

			assert.Equal(t, "registry-secret", pullSecret["name"])

			containers := spec["containers"].([]any)
			require.Len(t, containers, 1)

			container := containers[0].(map[string]any)

			assert.Equal(t, "api", container["name"])

			assert.Equal(t, "nginx:latest", container["image"])

			env := container["env"].([]any)
			require.Len(t, env, 3)

			db := env[0].(map[string]any)

			assert.Equal(t, "postgres://user:s3cret@db:5432/app", db["value"])

			secret := env[1].(map[string]any)

			valueFrom := secret["valueFrom"].(map[string]any)

			secretKey := valueFrom["secretKeyRef"].(map[string]any)

			assert.Equal(t, "payment-secret", secretKey["name"])

			config := env[2].(map[string]any)

			valueFrom = config["valueFrom"].(map[string]any)

			configMap := valueFrom["configMapKeyRef"].(map[string]any)

			assert.Equal(t, "payment-config", configMap["name"])

			envFrom := container["envFrom"].([]any)
			require.Len(t, envFrom, 2)

			secretRef := envFrom[0].(map[string]any)

			secretObj := secretRef["secretRef"].(map[string]any)

			assert.Equal(t, "application-secret", secretObj["name"])

			configRef := envFrom[1].(map[string]any)

			configObj := configRef["configMapRef"].(map[string]any)

			assert.Equal(t, "application-config", configObj["name"])

			source, ok := resource["source"].(map[string]any)
			require.True(t, ok, "source should be an object")

			assert.Equal(t, "/workspace/manifests/nginx/deployment.yaml", source["path"])
			assert.Equal(t, "manifests/nginx/deployment.yaml", source["relativePath"])

			rule, ok := rules[0].(map[string]any)
			require.True(t, ok, "rule should be an object")

			paths, ok := rule["paths"].([]any)
			require.True(t, ok, "paths should be an array")
			require.Len(t, paths, 1)

			path, ok := paths[0].(map[string]any)
			require.True(t, ok, "path should be an object")
			assert.Equal(t, resourceID, path["resourceID"])

			related, ok := rule["relatedResourcesIDs"].([]any)
			require.True(t, ok, "relatedResourcesIDs should be an array")

			require.Len(t, related, 1)
			assert.Equal(t, resourceID, related[0])
		})
	}
}
