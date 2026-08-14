package reportcrypto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMasterKey    = "01234567890123456789012345678901"
	testMasterKeyEnv = "KUBESCAPE_MASTER_KEY"
)

type encryptedReportFixture struct {
	data               []byte
	dek                []byte
	encryptedID        string
	decryptedID        string
	encryptedName      string
	encryptedNamespace string
	encryptedLabel     string
}

func TestDecryptReportRestoresEveryReportCopy(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)

	decrypted, err := DecryptReport(fixture.data, []byte(testMasterKey))
	require.NoError(t, err)

	report := decodeTestObject(t, decrypted)
	assert.Equal(t, "keep-at-top-level", report["futureReportField"])
	assert.Equal(t, true, report["scanCoverage"].(map[string]any)["degraded"])

	metadata := requireTestObject(t, report, "metadata")
	assert.Equal(t, "keep-in-metadata", metadata["futureMetadataField"])
	target := requireTestObject(t, metadata, "targetMetadata")
	repository := requireTestObject(t, target, "gitRepoContextMetadata")
	assert.Equal(t, "kubescape", repository["repo"])
	assert.Equal(t, "kubescape", repository["owner"])
	assert.Equal(t, "fix/report-roundtrip", repository["branch"])
	assert.Equal(t, "main", repository["defaultBranch"])
	assert.Equal(t, "https://github.com/kubescape/kubescape.git", repository["remoteURL"])
	assert.Equal(t, "/workspace/kubescape", repository["localRootPath"])
	assert.Equal(t, "keep-in-repository", repository["futureRepositoryField"])
	commit := requireTestObject(t, repository, "lastCommit")
	assert.Equal(t, "0123456789abcdef", commit["hash"])
	assert.Equal(t, "Kubescape Maintainer", commit["committerName"])
	assert.Equal(t, "maintainer@example.com", commit["committerEmail"])
	assert.Equal(t, "fix encrypted report decryption", commit["message"])
	assert.Equal(t, "keep-in-commit", commit["futureCommitField"])

	resources := requireTestArray(t, report, "resources")
	require.Len(t, resources, 1)
	resource := resources[0].(map[string]any)
	assertDecryptedResource(t, resource, fixture.decryptedID)
	assert.Equal(t, "keep-on-resource", resource["futureResourceField"])
	assert.Equal(t, "keep-in-source", requireTestObject(t, resource, "source")["futureSourceField"])

	results := requireTestArray(t, report, "results")
	require.Len(t, results, 1)
	result := results[0].(map[string]any)
	assert.Equal(t, fixture.decryptedID, result["resourceID"])
	assert.Equal(t, "keep-on-result", result["futureResultField"])

	rawResource := requireTestObject(t, result, "rawResource")
	assertDecryptedResource(t, rawResource, fixture.decryptedID)
	assert.Equal(t, "keep-on-raw-resource", rawResource["futureRawResourceField"])

	prioritized := requireTestObject(t, result, "prioritizedResource")
	assert.Equal(t, fixture.decryptedID, prioritized["resourceID"])
	assert.Equal(t, "keep-on-priority", prioritized["futurePriorityField"])

	controls := requireTestArray(t, result, "controls")
	require.Len(t, controls, 1)
	control := controls[0].(map[string]any)
	assert.Equal(t, "keep-on-control", control["futureControlField"])
	rules := requireTestArray(t, control, "rules")
	require.Len(t, rules, 1)
	rule := rules[0].(map[string]any)
	assert.Equal(t, "keep-on-rule", rule["futureRuleField"])
	paths := requireTestArray(t, rule, "paths")
	require.Len(t, paths, 2)
	assert.Equal(t, fixture.decryptedID, paths[0].(map[string]any)["resourceID"])
	assert.Equal(t, "unmapped-resource", paths[1].(map[string]any)["resourceID"])
	related := requireTestArray(t, rule, "relatedResourcesIDs")
	assert.Equal(t, []any{fixture.decryptedID, "unmapped-resource"}, related)

	resourceLabels := requireTestObject(t, report, "resourceLabels")
	require.NotContains(t, resourceLabels, fixture.encryptedID)
	labels := requireTestObject(t, resourceLabels, fixture.decryptedID)
	assert.Equal(t, "backend", labels["team"])
	assert.Equal(t, "payments", labels["app.kubernetes.io/name"])
}

func TestDecryptReportSupportsRawResourceOnlyReports(t *testing.T) {
	fixture := newEncryptedReportFixture(t, false, true)

	decrypted, err := DecryptReport(fixture.data, []byte(testMasterKey))
	require.NoError(t, err)

	report := decodeTestObject(t, decrypted)
	assert.NotContains(t, report, "resources")

	results := requireTestArray(t, report, "results")
	require.Len(t, results, 1)
	result := results[0].(map[string]any)
	assert.Equal(t, fixture.decryptedID, result["resourceID"])
	assertDecryptedResource(t, requireTestObject(t, result, "rawResource"), fixture.decryptedID)

	labels := requireTestObject(t, report, "resourceLabels")
	assert.Contains(t, labels, fixture.decryptedID)
	assert.NotContains(t, labels, fixture.encryptedID)
}

func TestDecryptReportSupportsResourceListOnlyReports(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, false)

	decrypted, err := DecryptReport(fixture.data, []byte(testMasterKey))
	require.NoError(t, err)

	report := decodeTestObject(t, decrypted)
	resources := requireTestArray(t, report, "resources")
	require.Len(t, resources, 1)
	assertDecryptedResource(t, resources[0].(map[string]any), fixture.decryptedID)

	results := requireTestArray(t, report, "results")
	require.Len(t, results, 1)
	result := results[0].(map[string]any)
	assert.NotContains(t, result, "rawResource")
	assert.Equal(t, fixture.decryptedID, result["resourceID"])
}

func TestDecryptReportLeavesPlaintextFieldsUntouched(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	report := decodeTestObject(t, fixture.data)

	resources := requireTestArray(t, report, "resources")
	resource := resources[0].(map[string]any)
	object := requireTestObject(t, resource, "object")
	metadata := requireTestObject(t, object, "metadata")
	labels := requireTestObject(t, metadata, "labels")
	labels["plaintext"] = "  keep surrounding whitespace  "
	annotations := requireTestObject(t, metadata, "annotations")
	annotations["multiline"] = "line one\nline two\n"

	fixture.data = mustMarshalTestJSON(t, report)
	decrypted, err := DecryptReport(fixture.data, []byte(testMasterKey))
	require.NoError(t, err)

	output := decodeTestObject(t, decrypted)
	outputResource := requireTestArray(t, output, "resources")[0].(map[string]any)
	outputObject := requireTestObject(t, outputResource, "object")
	outputMetadata := requireTestObject(t, outputObject, "metadata")
	assert.Equal(t, "  keep surrounding whitespace  ", requireTestObject(t, outputMetadata, "labels")["plaintext"])
	assert.Equal(t, "line one\nline two\n", requireTestObject(t, outputMetadata, "annotations")["multiline"])
}

func TestDecryptReportPreservesNullOptionalSections(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	report := decodeTestObject(t, fixture.data)

	resources := requireTestArray(t, report, "resources")
	resources[0].(map[string]any)["source"] = nil
	results := requireTestArray(t, report, "results")
	result := results[0].(map[string]any)
	result["prioritizedResource"] = nil
	result["controls"] = nil
	result["rawResource"].(map[string]any)["source"] = nil
	report["resourceLabels"] = nil

	decrypted, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.NoError(t, err)

	output := decodeTestObject(t, decrypted)
	outputResource := requireTestArray(t, output, "resources")[0].(map[string]any)
	assert.Nil(t, outputResource["source"])
	outputResult := requireTestArray(t, output, "results")[0].(map[string]any)
	assert.Nil(t, outputResult["prioritizedResource"])
	assert.Nil(t, outputResult["controls"])
	assert.Nil(t, outputResult["rawResource"].(map[string]any)["source"])
	assert.Nil(t, output["resourceLabels"])
}

func TestDecryptReportHandlesMissingOptionalSections(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	report := decodeTestObject(t, fixture.data)
	delete(report, "resources")
	delete(report, "results")
	delete(report, "resourceLabels")

	decrypted, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.NoError(t, err)

	output := decodeTestObject(t, decrypted)
	assert.NotContains(t, output, "resources")
	assert.NotContains(t, output, "results")
	assert.NotContains(t, output, "resourceLabels")
	metadata := requireTestObject(t, output, "metadata")
	repository := requireTestObject(t, requireTestObject(t, metadata, "targetMetadata"), "gitRepoContextMetadata")
	assert.Equal(t, "kubescape", repository["repo"])
}

func TestDecryptReportRejectsIncorrectMasterKey(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)

	_, err := DecryptReport(fixture.data, []byte("abcdefghijklmnopqrstuvwxyzABCDEF"))
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "decrypt")
}

func TestDecryptReportRejectsTamperedCiphertext(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	report := decodeTestObject(t, fixture.data)
	resources := requireTestArray(t, report, "resources")
	object := requireTestObject(t, resources[0].(map[string]any), "object")
	metadata := requireTestObject(t, object, "metadata")
	metadata["name"] = fixture.encryptedName[:len(fixture.encryptedName)-2] + "AA"

	_, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resources[0]")
	assert.Contains(t, err.Error(), "metadata")
}

func TestDecryptReportSupportsMultipleEncryptedAliasesForResource(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, false)
	report := decodeTestObject(t, fixture.data)
	resources := requireTestArray(t, report, "resources")

	duplicate := deepCopyTestObject(t, resources[0].(map[string]any))
	duplicate["resourceID"] = "different-encrypted-id"
	report["resources"] = append(resources, duplicate)

	decrypted, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.NoError(t, err)

	output := decodeTestObject(t, decrypted)
	decryptedResources := requireTestArray(t, output, "resources")
	require.Len(t, decryptedResources, 2)
	assert.Equal(t, fixture.decryptedID, decryptedResources[0].(map[string]any)["resourceID"])
	assert.Equal(t, fixture.decryptedID, decryptedResources[1].(map[string]any)["resourceID"])
}

func TestDecryptReportRejectsResourceLabelCollisions(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	report := decodeTestObject(t, fixture.data)
	labels := requireTestObject(t, report, "resourceLabels")
	labels[fixture.decryptedID] = map[string]any{"team": "plaintext"}

	_, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting value")
}

func TestDecryptReportMergesLabelsFromResourceAliases(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	report := decodeTestObject(t, fixture.data)
	labels := requireTestObject(t, report, "resourceLabels")
	labels[fixture.decryptedID] = map[string]any{"cost-center": "security"}

	decrypted, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
	require.NoError(t, err)

	output := decodeTestObject(t, decrypted)
	labelsByResource := requireTestObject(t, output, "resourceLabels")
	restored := requireTestObject(t, labelsByResource, fixture.decryptedID)
	assert.Equal(t, "backend", restored["team"])
	assert.Equal(t, "payments", restored["app.kubernetes.io/name"])
	assert.Equal(t, "security", restored["cost-center"])
}

func TestDecryptReportValidationErrorsIncludeFieldContext(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)

	tests := []struct {
		name        string
		mutate      func(map[string]any)
		wantError   string
		wantContext string
	}{
		{
			name: "empty report",
			mutate: func(report map[string]any) {
				for key := range report {
					delete(report, key)
				}
			},
			wantError: "metadata not found",
		},
		{
			name: "null metadata",
			mutate: func(report map[string]any) {
				report["metadata"] = nil
			},
			wantError: "metadata not found",
		},
		{
			name: "metadata array",
			mutate: func(report map[string]any) {
				report["metadata"] = []any{}
			},
			wantError: "failed to parse metadata",
		},
		{
			name: "resources object",
			mutate: func(report map[string]any) {
				report["resources"] = map[string]any{}
			},
			wantError: "failed to parse resources",
		},
		{
			name: "resource scalar",
			mutate: func(report map[string]any) {
				report["resources"] = []any{"not-an-object"}
			},
			wantError: "failed to parse resources",
		},
		{
			name: "resource ID number",
			mutate: func(report map[string]any) {
				resources := requireTestArray(t, report, "resources")
				resources[0].(map[string]any)["resourceID"] = 42
			},
			wantError:   "failed to parse",
			wantContext: "resources[0].resourceID",
		},
		{
			name: "resource object scalar",
			mutate: func(report map[string]any) {
				resources := requireTestArray(t, report, "resources")
				resources[0].(map[string]any)["object"] = "not-a-workload"
			},
			wantError:   "failed to parse",
			wantContext: "resources[0].object",
		},
		{
			name: "resource source scalar",
			mutate: func(report map[string]any) {
				resources := requireTestArray(t, report, "resources")
				resources[0].(map[string]any)["source"] = "not-a-source"
			},
			wantError:   "failed to parse",
			wantContext: "resources[0].source",
		},
		{
			name: "results object",
			mutate: func(report map[string]any) {
				report["results"] = map[string]any{}
			},
			wantError: "failed to parse results",
		},
		{
			name: "result ID number",
			mutate: func(report map[string]any) {
				results := requireTestArray(t, report, "results")
				results[0].(map[string]any)["resourceID"] = 42
			},
			wantError:   "failed to parse",
			wantContext: "results[0].resourceID",
		},
		{
			name: "raw resource array",
			mutate: func(report map[string]any) {
				results := requireTestArray(t, report, "results")
				results[0].(map[string]any)["rawResource"] = []any{}
			},
			wantError:   "failed to parse",
			wantContext: "results[0].rawResource",
		},
		{
			name: "prioritized resource array",
			mutate: func(report map[string]any) {
				results := requireTestArray(t, report, "results")
				results[0].(map[string]any)["prioritizedResource"] = []any{}
			},
			wantError:   "failed to parse",
			wantContext: "results[0].prioritizedResource",
		},
		{
			name: "controls object",
			mutate: func(report map[string]any) {
				results := requireTestArray(t, report, "results")
				results[0].(map[string]any)["controls"] = map[string]any{}
			},
			wantError:   "failed to parse",
			wantContext: "results[0].controls",
		},
		{
			name: "rules scalar",
			mutate: func(report map[string]any) {
				result := requireTestArray(t, report, "results")[0].(map[string]any)
				control := requireTestArray(t, result, "controls")[0].(map[string]any)
				control["rules"] = "not-rules"
			},
			wantError:   "failed to parse",
			wantContext: "results[0].controls[0].rules",
		},
		{
			name: "paths object",
			mutate: func(report map[string]any) {
				result := requireTestArray(t, report, "results")[0].(map[string]any)
				control := requireTestArray(t, result, "controls")[0].(map[string]any)
				rule := requireTestArray(t, control, "rules")[0].(map[string]any)
				rule["paths"] = map[string]any{}
			},
			wantError:   "failed to parse",
			wantContext: "results[0].controls[0].rules[0].paths",
		},
		{
			name: "related resource IDs contain number",
			mutate: func(report map[string]any) {
				result := requireTestArray(t, report, "results")[0].(map[string]any)
				control := requireTestArray(t, result, "controls")[0].(map[string]any)
				rule := requireTestArray(t, control, "rules")[0].(map[string]any)
				rule["relatedResourcesIDs"] = []any{42}
			},
			wantError:   "failed to parse",
			wantContext: "relatedResourcesIDs",
		},
		{
			name: "resource labels array",
			mutate: func(report map[string]any) {
				report["resourceLabels"] = []any{}
			},
			wantError: "failed to parse resourceLabels",
		},
		{
			name: "resource label set scalar",
			mutate: func(report map[string]any) {
				labels := requireTestObject(t, report, "resourceLabels")
				labels[fixture.encryptedID] = "not-labels"
			},
			wantError:   "failed to parse",
			wantContext: "resourceLabels",
		},
		{
			name: "resource label value number",
			mutate: func(report map[string]any) {
				labels := requireTestObject(t, report, "resourceLabels")
				labels[fixture.encryptedID].(map[string]any)["team"] = 42
			},
			wantError:   "failed to parse",
			wantContext: "team",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := decodeTestObject(t, fixture.data)
			tt.mutate(report)

			_, err := DecryptReport(mustMarshalTestJSON(t, report), []byte(testMasterKey))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
			if tt.wantContext != "" {
				assert.Contains(t, err.Error(), tt.wantContext)
			}
		})
	}
}

func TestDecryptReportRejectsInvalidTopLevelJSON(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantError string
	}{
		{name: "empty", data: "", wantError: "report is empty"},
		{name: "whitespace", data: " \n\t", wantError: "report is empty"},
		{name: "truncated", data: `{`, wantError: "failed to parse report"},
		{name: "array", data: `[]`, wantError: "failed to parse report"},
		{name: "null", data: `null`, wantError: "expected an object"},
		{name: "string", data: `"report"`, wantError: "failed to parse report"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptReport([]byte(tt.data), []byte(testMasterKey))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestDecryptReportFromEnv(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	t.Setenv(testMasterKeyEnv, testMasterKey)

	decrypted, err := DecryptReportFromEnv(fixture.data)
	require.NoError(t, err)
	report := decodeTestObject(t, decrypted)
	assert.Equal(t, fixture.decryptedID, requireTestArray(t, report, "results")[0].(map[string]any)["resourceID"])
}

func TestDecryptReportFromEnvRequiresKey(t *testing.T) {
	fixture := newEncryptedReportFixture(t, true, true)
	t.Setenv(testMasterKeyEnv, "")

	_, err := DecryptReportFromEnv(fixture.data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), testMasterKeyEnv)
}

func newEncryptedReportFixture(t *testing.T, includeResources, includeRawResource bool) encryptedReportFixture {
	t.Helper()

	dek, err := GenerateDEK()
	require.NoError(t, err)
	encrypt := func(value string) string {
		t.Helper()
		encrypted, err := EncryptString(value, dek)
		require.NoError(t, err)
		return encrypted
	}

	encryptedName := encrypt("payments-api")
	encryptedNamespace := encrypt("production")
	encryptedLabel := encrypt("backend")
	encryptedApplicationLabel := encrypt("payments")
	encryptedAnnotation := encrypt("platform-team")
	encryptedNestedAnnotation := encrypt("pod-template-owner")
	encryptedSourcePath := encrypt("/workspace/kubescape/manifests/payments.yaml")
	encryptedContainerName := encrypt("api")
	encryptedInitContainerName := encrypt("migrate")
	encryptedEphemeralContainerName := encrypt("debugger")
	encryptedImage := encrypt("registry.example.com/payments:v1.2.3")
	encryptedInitImage := encrypt("registry.example.com/migrate:v4")
	encryptedEphemeralImage := encrypt("registry.example.com/debug:v2")
	encryptedEnvValue := encrypt("postgres://user:secret@database:5432/payments")
	encryptedSecretRef := encrypt("payments-database")
	encryptedConfigMapRef := encrypt("payments-settings")
	encryptedEnvFromSecret := encrypt("payments-runtime")
	encryptedEnvFromConfigMap := encrypt("payments-environment")
	encryptedImagePullSecret := encrypt("private-registry")
	encryptedServiceAccount := encrypt("payments-service-account")

	object := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"sourcePath": encryptedSourcePath + ":37",
		"futureObjectField": map[string]any{
			"enabled": true,
		},
		"metadata": map[string]any{
			"name":      encryptedName,
			"namespace": encryptedNamespace,
			"labels": map[string]any{
				"team":                   encryptedLabel,
				"app.kubernetes.io/name": encryptedApplicationLabel,
				"plaintext":              "leave-me-alone",
			},
			"annotations": map[string]any{
				"owner":     encryptedAnnotation,
				"plaintext": "leave-this-too",
			},
		},
		"spec": map[string]any{
			"replicas":           2,
			"serviceAccountName": encryptedServiceAccount,
			"imagePullSecrets": []any{
				map[string]any{"name": encryptedImagePullSecret},
			},
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{
						"owner": encryptedNestedAnnotation,
					},
				},
				"spec": map[string]any{
					"containers": []any{
						map[string]any{
							"name":  encryptedContainerName,
							"image": encryptedImage,
							"env": []any{
								map[string]any{
									"name":  "DATABASE_URL",
									"value": encryptedEnvValue,
								},
								map[string]any{
									"name": "PASSWORD",
									"valueFrom": map[string]any{
										"secretKeyRef": map[string]any{
											"name": encryptedSecretRef,
											"key":  "password",
										},
									},
								},
								map[string]any{
									"name": "LOG_LEVEL",
									"valueFrom": map[string]any{
										"configMapKeyRef": map[string]any{
											"name": encryptedConfigMapRef,
											"key":  "level",
										},
									},
								},
							},
							"envFrom": []any{
								map[string]any{
									"secretRef": map[string]any{"name": encryptedEnvFromSecret},
								},
								map[string]any{
									"configMapRef": map[string]any{"name": encryptedEnvFromConfigMap},
								},
							},
						},
					},
					"initContainers": []any{
						map[string]any{
							"name":  encryptedInitContainerName,
							"image": encryptedInitImage,
						},
					},
					"ephemeralContainers": []any{
						map[string]any{
							"name":  encryptedEphemeralContainerName,
							"image": encryptedEphemeralImage,
						},
					},
				},
			},
		},
	}

	workloadBytes := mustMarshalTestJSON(t, object)
	workload, err := workloadinterface.NewWorkload(workloadBytes)
	require.NoError(t, err)
	encryptedID := workload.GetID()
	decryptedID := "apps/v1/production/Deployment/payments-api"

	source := map[string]any{
		"path":                   encrypt("/workspace/kubescape/manifests/payments.yaml"),
		"relativePath":           encrypt("manifests/payments.yaml"),
		"helmPath":               encrypt("charts/payments"),
		"helmChartName":          encrypt("payments"),
		"helmTemplateFile":       encrypt("templates/deployment.yaml"),
		"helmValuesPaths":        []any{encrypt("values.yaml"), encrypt("values/production.yaml")},
		"kustomizeDirectoryName": encrypt("overlays/production"),
		"futureSourceField":      "keep-in-source",
		"lastCommit": map[string]any{
			"hash":           encrypt("fedcba9876543210"),
			"committerName":  encrypt("Source Author"),
			"committerEmail": encrypt("source@example.com"),
			"message":        encrypt("update payments manifest"),
			"futureField":    "keep-in-source-commit",
		},
	}

	resource := map[string]any{
		"resourceID":          encryptedID,
		"object":              object,
		"source":              source,
		"futureResourceField": "keep-on-resource",
	}
	rawResource := deepCopyTestObject(t, resource)
	rawResource["futureRawResourceField"] = "keep-on-raw-resource"

	wrappedDEK, err := WrapDEK(dek, []byte(testMasterKey))
	require.NoError(t, err)

	result := map[string]any{
		"resourceID": encryptedID,
		"prioritizedResource": map[string]any{
			"resourceID":          encryptedID,
			"severity":            4,
			"futurePriorityField": "keep-on-priority",
		},
		"controls": []any{
			map[string]any{
				"controlID":          "C-0010",
				"name":               "Container Resources",
				"futureControlField": "keep-on-control",
				"rules": []any{
					map[string]any{
						"name":            "Resource limits",
						"futureRuleField": "keep-on-rule",
						"paths": []any{
							map[string]any{"resourceID": encryptedID, "failedPath": "spec.template.spec.containers[0]"},
							map[string]any{"resourceID": "unmapped-resource", "failedPath": "metadata"},
						},
						"relatedResourcesIDs": []any{encryptedID, "unmapped-resource"},
					},
				},
			},
		},
		"futureResultField": "keep-on-result",
	}
	if includeRawResource {
		result["rawResource"] = rawResource
	}

	report := map[string]any{
		"generationTime": "2026-08-14T12:00:00Z",
		"metadata": map[string]any{
			"targetMetadata": map[string]any{
				"gitRepoContextMetadata": map[string]any{
					"provider":              "github",
					"repo":                  encrypt("kubescape"),
					"owner":                 encrypt("kubescape"),
					"branch":                encrypt("fix/report-roundtrip"),
					"defaultBranch":         encrypt("main"),
					"remoteURL":             encrypt("https://github.com/kubescape/kubescape.git"),
					"localRootPath":         encrypt("/workspace/kubescape"),
					"futureRepositoryField": "keep-in-repository",
					"lastCommit": map[string]any{
						"hash":              encrypt("0123456789abcdef"),
						"committerName":     encrypt("Kubescape Maintainer"),
						"committerEmail":    encrypt("maintainer@example.com"),
						"message":           encrypt("fix encrypted report decryption"),
						"futureCommitField": "keep-in-commit",
					},
				},
			},
			"encryptionMetadata": map[string]any{
				"version":      "v1",
				"dekAlgorithm": "AES256_GCM",
				"kekAlgorithm": "AES256_GCM",
				"encryptedDEK": wrappedDEK,
			},
			"futureMetadataField": "keep-in-metadata",
		},
		"results": []any{result},
		"resourceLabels": map[string]any{
			encryptedID: map[string]any{
				"team":                   encryptedLabel,
				"app.kubernetes.io/name": encryptedApplicationLabel,
			},
		},
		"scanCoverage": map[string]any{
			"degraded": true,
		},
		"futureReportField": "keep-at-top-level",
	}
	if includeResources {
		report["resources"] = []any{resource}
	}

	return encryptedReportFixture{
		data:               mustMarshalTestJSON(t, report),
		dek:                dek,
		encryptedID:        encryptedID,
		decryptedID:        decryptedID,
		encryptedName:      encryptedName,
		encryptedNamespace: encryptedNamespace,
		encryptedLabel:     encryptedLabel,
	}
}

func assertDecryptedResource(t *testing.T, resource map[string]any, expectedID string) {
	t.Helper()

	assert.Equal(t, expectedID, resource["resourceID"])
	object := requireTestObject(t, resource, "object")
	assert.Equal(t, "/workspace/kubescape/manifests/payments.yaml:37", object["sourcePath"])
	assert.Equal(t, true, requireTestObject(t, object, "futureObjectField")["enabled"])

	metadata := requireTestObject(t, object, "metadata")
	assert.Equal(t, "payments-api", metadata["name"])
	assert.Equal(t, "production", metadata["namespace"])
	labels := requireTestObject(t, metadata, "labels")
	assert.Equal(t, "backend", labels["team"])
	assert.Equal(t, "payments", labels["app.kubernetes.io/name"])
	assert.Equal(t, "leave-me-alone", labels["plaintext"])
	annotations := requireTestObject(t, metadata, "annotations")
	assert.Equal(t, "platform-team", annotations["owner"])
	assert.Equal(t, "leave-this-too", annotations["plaintext"])

	spec := requireTestObject(t, object, "spec")
	assert.Equal(t, "payments-service-account", spec["serviceAccountName"])
	pullSecrets := requireTestArray(t, spec, "imagePullSecrets")
	assert.Equal(t, "private-registry", pullSecrets[0].(map[string]any)["name"])

	template := requireTestObject(t, spec, "template")
	templateMetadata := requireTestObject(t, template, "metadata")
	assert.Equal(t, "pod-template-owner", requireTestObject(t, templateMetadata, "annotations")["owner"])
	podSpec := requireTestObject(t, template, "spec")
	containers := requireTestArray(t, podSpec, "containers")
	container := containers[0].(map[string]any)
	assert.Equal(t, "api", container["name"])
	assert.Equal(t, "registry.example.com/payments:v1.2.3", container["image"])
	env := requireTestArray(t, container, "env")
	assert.Equal(t, "postgres://user:secret@database:5432/payments", env[0].(map[string]any)["value"])
	secretValueFrom := requireTestObject(t, env[1].(map[string]any), "valueFrom")
	assert.Equal(t, "payments-database", requireTestObject(t, secretValueFrom, "secretKeyRef")["name"])
	configValueFrom := requireTestObject(t, env[2].(map[string]any), "valueFrom")
	assert.Equal(t, "payments-settings", requireTestObject(t, configValueFrom, "configMapKeyRef")["name"])
	envFrom := requireTestArray(t, container, "envFrom")
	assert.Equal(t, "payments-runtime", requireTestObject(t, envFrom[0].(map[string]any), "secretRef")["name"])
	assert.Equal(t, "payments-environment", requireTestObject(t, envFrom[1].(map[string]any), "configMapRef")["name"])

	initContainers := requireTestArray(t, podSpec, "initContainers")
	assert.Equal(t, "migrate", initContainers[0].(map[string]any)["name"])
	assert.Equal(t, "registry.example.com/migrate:v4", initContainers[0].(map[string]any)["image"])
	ephemeralContainers := requireTestArray(t, podSpec, "ephemeralContainers")
	assert.Equal(t, "debugger", ephemeralContainers[0].(map[string]any)["name"])
	assert.Equal(t, "registry.example.com/debug:v2", ephemeralContainers[0].(map[string]any)["image"])

	source := requireTestObject(t, resource, "source")
	assert.Equal(t, "/workspace/kubescape/manifests/payments.yaml", source["path"])
	assert.Equal(t, "manifests/payments.yaml", source["relativePath"])
	assert.Equal(t, "charts/payments", source["helmPath"])
	assert.Equal(t, "payments", source["helmChartName"])
	assert.Equal(t, "templates/deployment.yaml", source["helmTemplateFile"])
	assert.Equal(t, []any{"values.yaml", "values/production.yaml"}, source["helmValuesPaths"])
	assert.Equal(t, "overlays/production", source["kustomizeDirectoryName"])
	assert.Equal(t, "keep-in-source", source["futureSourceField"])
	sourceCommit := requireTestObject(t, source, "lastCommit")
	assert.Equal(t, "fedcba9876543210", sourceCommit["hash"])
	assert.Equal(t, "Source Author", sourceCommit["committerName"])
	assert.Equal(t, "source@example.com", sourceCommit["committerEmail"])
	assert.Equal(t, "update payments manifest", sourceCommit["message"])
	assert.Equal(t, "keep-in-source-commit", sourceCommit["futureField"])
}

func decodeTestObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var object map[string]any
	require.NoError(t, json.Unmarshal(data, &object))
	require.NotNil(t, object)
	return object
}

func requireTestObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key]
	require.True(t, ok, "%s should be present", key)
	object, ok := value.(map[string]any)
	require.True(t, ok, "%s should be an object, got %T", key, value)
	return object
}

func requireTestArray(t *testing.T, parent map[string]any, key string) []any {
	t.Helper()
	value, ok := parent[key]
	require.True(t, ok, "%s should be present", key)
	array, ok := value.([]any)
	require.True(t, ok, "%s should be an array, got %T", key, value)
	return array
}

func mustMarshalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return data
}

func deepCopyTestObject(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	return decodeTestObject(t, mustMarshalTestJSON(t, object))
}
