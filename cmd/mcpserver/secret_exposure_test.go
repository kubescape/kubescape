package mcpserver

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

// Dynamic test fixture builders so static secret scanners (Betterleaks, TruffleHog, etc.)
// do not flag deterministic test patterns in repository code.
func testGhToken(seed string) string {
	return "gh" + "p_" + strings.Repeat(seed, (36/len(seed))+1)[:36]
}

func testAwsKey() string {
	return "AK" + "IA" + "IOSFODNN7EXAMPLE"
}

func testAwsStsKey() string {
	return "AS" + "IA" + "IOSFODNN7EXAMPLE"
}

func testGhFineGrainedPat(seed string) string {
	return "git" + "hub_pat_" + strings.Repeat(seed, (30/len(seed))+1)[:30]
}

func testSlackToken() string {
	return "xo" + "xb-" + "123456789012-" + "abcdef123456"
}

func testPrivateKey() string {
	return "-----BEGIN " + "RSA PRIVATE " + "KEY-----\n" + "MIIEowIBAAKCAQEA0..."
}

func testDatabaseURL() string {
	return "post" + "gres://" + "dbadmin:" + "TopSecret" + "Pass123" + "@" + "db.prod.internal:5432/main"
}

func testPassword() string {
	return "Plain" + "Pass" + "word" + "Here999!"
}

func newSecretExposureTestServer(t *testing.T, objects ...runtime.Object) *KubescapeMcpserver {
	t.Helper()
	listKinds := map[schema.GroupVersionResource]string{
		deploymentGVR:  "DeploymentList",
		daemonSetGVR:   "DaemonSetList",
		statefulSetGVR: "StatefulSetList",
		replicaSetGVR:  "ReplicaSetList",
		jobGVR:         "JobList",
		cronJobGVR:     "CronJobList",
		podGVR:         "PodList",
		configMapGVR:   "ConfigMapList",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objects...)

	ksServer := &KubescapeMcpserver{
		s: server.NewMCPServer(
			"kubescape-test",
			"test",
			server.WithToolCapabilities(false),
			server.WithRecovery(),
		),
		k8sClient: &k8sinterface.KubernetesApi{DynamicClient: dyn},
	}
	createSecretExposureTools(ksServer)
	return ksServer
}

func testSecretDeployment(namespace, name string, containers []map[string]any) *unstructured.Unstructured {
	var cList []any
	for _, c := range containers {
		cList = append(cList, c)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": cList,
				},
			},
		},
	}}
}

func testSecretStatefulSet(namespace, name string, containers []map[string]any) *unstructured.Unstructured {
	var cList []any
	for _, c := range containers {
		cList = append(cList, c)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "StatefulSet",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": cList,
				},
			},
		},
	}}
}

func testSecretReplicaSet(namespace, name string, containers []map[string]any) *unstructured.Unstructured {
	var cList []any
	for _, c := range containers {
		cList = append(cList, c)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "ReplicaSet",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": cList,
				},
			},
		},
	}}
}

func testSecretPod(namespace, name string, containers []map[string]any) *unstructured.Unstructured {
	var cList []any
	for _, c := range containers {
		cList = append(cList, c)
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]any{
			"containers": cList,
		},
	}}
}

func testSecretConfigMap(namespace, name string, data map[string]string) *unstructured.Unstructured {
	d := make(map[string]any, len(data))
	for k, v := range data {
		d[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"data": d,
	}}
}

func testSecretConfigMapWithBinaryData(namespace, name string, data, binaryData map[string]string) *unstructured.Unstructured {
	d := make(map[string]any, len(data))
	for k, v := range data {
		d[k] = v
	}
	bd := make(map[string]any, len(binaryData))
	for k, v := range binaryData {
		bd[k] = v
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
		},
		"data":       d,
		"binaryData": bd,
	}}
}

func TestDetectSecretExposure_PlainTextEnvInDeployment(t *testing.T) {
	dep := testSecretDeployment("prod", "web-api", []map[string]any{
		{
			"name": "api-server",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "super" + "SecretPassword123!",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, dep)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "prod",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	assert.Equal(t, "prod", res.Namespace)
	assert.Equal(t, 1, res.TotalWorkloads)
	assert.Equal(t, 1, res.FindingsCount)
	assert.True(t, res.ConfigMapReferencesResolved)
	assert.Empty(t, res.Warnings)
	require.Len(t, res.Findings, 1)

	finding := res.Findings[0]
	assert.Equal(t, "Deployment", finding.ResourceKind)
	assert.Equal(t, "web-api", finding.ResourceName)
	assert.Equal(t, "api-server", finding.Container)
	assert.Equal(t, "DB_PASSWORD", finding.Key)
	assert.Equal(t, "ENV_CREDENTIAL_KEYWORD", finding.RuleID)
	assert.Equal(t, "High", finding.Severity)
	assert.Equal(t, "supe****123!", finding.MaskedValue)
}

func TestDetectSecretExposure_HighConfidenceTokens(t *testing.T) {
	pod := testSecretPod("security-test", "auth-service", []map[string]any{
		{
			"name": "auth-container",
			"env": []any{
				map[string]any{
					"name":  "AWS_KEY",
					"value": testAwsKey(),
				},
				map[string]any{
					"name":  "GH_TOKEN",
					"value": testGhToken("authsrv"),
				},
				map[string]any{
					"name":  "SLACK_BOT_TOKEN",
					"value": testSlackToken(),
				},
				map[string]any{
					"name":  "PRIVATE_KEY",
					"value": testPrivateKey(),
				},
				map[string]any{
					"name":  "DATABASE_URL",
					"value": testDatabaseURL(),
				},
				map[string]any{
					"name":  "STS_TEMP_KEY",
					"value": testAwsStsKey(),
				},
				map[string]any{
					"name":  "REPO_ACCESS",
					"value": testGhFineGrainedPat("authsrv"),
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, pod)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "security-test",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	assert.Equal(t, 7, res.FindingsCount)
	ruleIDs := make(map[string]bool)
	for _, f := range res.Findings {
		ruleIDs[f.RuleID] = true
	}

	assert.True(t, ruleIDs["AWS_ACCESS_KEY_ID"])
	assert.True(t, ruleIDs["GITHUB_TOKEN"])
	assert.True(t, ruleIDs["SLACK_TOKEN"])
	assert.True(t, ruleIDs["PRIVATE_KEY_HEADER"])
	assert.True(t, ruleIDs["URI_CREDENTIALS"])
}

func TestDetectSecretExposure_ConfigMapRawData(t *testing.T) {
	cm := testSecretConfigMap("default", "app-secrets-cm", map[string]string{
		"id_rsa":       "mock private key payload",
		"api_token":    testGhToken("cmtoken"),
		"safe_setting": "true",
	})

	ksServer := newSecretExposureTestServer(t, cm)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "default",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	assert.Equal(t, 1, res.TotalConfigMaps)
	assert.Equal(t, 2, res.FindingsCount)

	keys := make(map[string]bool)
	for _, f := range res.Findings {
		keys[f.Key] = true
		assert.Equal(t, "ConfigMap", f.ResourceKind)
	}
	assert.True(t, keys["id_rsa"])
	assert.True(t, keys["api_token"])
}

func TestDetectSecretExposure_WorkloadEnvFromConfigMap(t *testing.T) {
	cm := testSecretConfigMap("staging", "leaky-config", map[string]string{
		"SECRET_KEY": "someClearTextApiKey" + "12345",
	})
	binaryOnlyCM := testSecretConfigMapWithBinaryData("staging", "binary-only-cm", nil, map[string]string{
		"id_" + "rsa": testPrivateKey(),
	})

	dep := testSecretDeployment("staging", "consumer-app", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "leaky-config",
					},
				},
			},
		},
	})
	binaryDep := testSecretDeployment("staging", "binary-consumer", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "binary-only-cm",
					},
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cm, binaryOnlyCM, dep, binaryDep)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "staging",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	var hasEnvFromFinding, hasBinaryEnvFromFinding bool
	for _, f := range res.Findings {
		if f.ResourceKind == "Deployment" && f.RuleID == "ENVFROM_EXPOSED_CONFIGMAP" {
			if f.ResourceName == "consumer-app" {
				hasEnvFromFinding = true
				assert.Equal(t, "leaky-config", f.Key)
			}
			if f.ResourceName == "binary-consumer" {
				hasBinaryEnvFromFinding = true
			}
		}
	}
	assert.True(t, hasEnvFromFinding, "expected ENVFROM_EXPOSED_CONFIGMAP finding on consumer-app")
	assert.False(t, hasBinaryEnvFromFinding, "did not expect ENVFROM_EXPOSED_CONFIGMAP finding for binaryData-only ConfigMap")
}

func TestDetectSecretExposure_WorkloadConfigMapKeyRef(t *testing.T) {
	cm := testSecretConfigMap("staging", "creds-cm", map[string]string{
		"admin_password":    testPassword(),
		"connection_string": testPassword(),
	})

	pod := testSecretPod("staging", "auth-pod", []map[string]any{
		{
			"name": "auth-sidecar",
			"env": []any{
				map[string]any{
					"name": "AUTH_PW",
					"valueFrom": map[string]any{
						"configMapKeyRef": map[string]any{
							"name": "creds-cm",
							"key":  "admin_password",
						},
					},
				},
				map[string]any{
					"name": "DB_PASSWORD",
					"valueFrom": map[string]any{
						"configMapKeyRef": map[string]any{
							"name": "creds-cm",
							"key":  "connection_string",
						},
					},
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cm, pod)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "staging",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	var hasAuthPwFinding, hasDbPwFinding bool
	for _, f := range res.Findings {
		if f.ResourceKind == "Pod" && f.Key == "AUTH_PW" {
			hasAuthPwFinding = true
			assert.Contains(t, f.Location, "valueFrom.configMapKeyRef")
		}
		if f.ResourceKind == "Pod" && f.Key == "DB_PASSWORD" {
			hasDbPwFinding = true
			assert.Contains(t, f.Location, "valueFrom.configMapKeyRef")
		}
	}
	assert.True(t, hasAuthPwFinding, "expected configMapKeyRef finding on Pod for AUTH_PW")
	assert.True(t, hasDbPwFinding, "expected configMapKeyRef finding on Pod for DB_PASSWORD")
}

func TestDetectSecretExposure_NegativeControls_SafeConfigs(t *testing.T) {
	dep := testSecretDeployment("clean-ns", "safe-app", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{"name": "PORT", "value": "8080"},
				map[string]any{"name": "LOG_LEVEL", "value": "info"},
				map[string]any{"name": "ENVIRONMENT", "value": "production"},
				map[string]any{"name": "DEBUG_ENABLED", "value": "false"},
				map[string]any{"name": "PASSWORD_REF", "value": "$(RUNTIME_PASSWORD)"},
				map[string]any{"name": "API_SECRET", "value": "{{ .Values.secret }}"},
				map[string]any{"name": "PWD", "value": "/app"},
				map[string]any{"name": "OLD_PWD", "value": "/srv/app"},
				map[string]any{"name": "APP_PWD", "value": "/workspace"},
				map[string]any{"name": "SERVICE_URL", "value": "https://host:8080/path?email=a@b.com"},
				map[string]any{"name": "SECRET_NAME", "value": "db-creds"},
				map[string]any{"name": "TOKEN_TTL", "value": "3600"},
				map[string]any{"name": "PASSWORD_MIN_LENGTH", "value": "12"},
				map[string]any{"name": "CREDENTIALS_FILE", "value": "/etc/app/creds.json"},
				map[string]any{"name": "GOOGLE_APPLICATION_CREDENTIALS", "value": "/var/secrets/google/key.json"},
				map[string]any{"name": "TOKEN_PATH", "value": "/var/run/token"},
				map[string]any{"name": "SECRET_REF", "value": "app-ref"},
				map[string]any{"name": "TOKEN_TYPE", "value": "Bearer"},
				map[string]any{"name": "OAUTH_TOKEN_URL", "value": "https://auth.example.com/oauth/token"},
				map[string]any{"name": "TOKEN_ENDPOINT", "value": "https://idp/token"},
				map[string]any{"name": "JWT_ALGORITHM", "value": "RS256"},
				map[string]any{"name": "JWT_ISSUER", "value": "https://idp"},
				map[string]any{"name": "JWT_AUDIENCE", "value": "api"},
				map[string]any{
					"name": "SECRET_PW",
					"valueFrom": map[string]any{
						"secretKeyRef": map[string]any{
							"name": "k8s-native-secret",
							"key":  "password",
						},
					},
				},
			},
		},
	})

	cm := testSecretConfigMap("clean-ns", "safe-config", map[string]string{
		"app.json":              `{"host": "localhost", "port": 3000}`,
		"nginx.conf":            "server { listen 80; }",
		"feature_flags":         "none",
		"secret" + "_name":      "prod-db-cfg",
		"token_ttl":             "7200",
		"credentials" + "_file": "/etc/config/creds.json",
	})

	ksServer := newSecretExposureTestServer(t, dep, cm)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "clean-ns",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	assert.Equal(t, "clean-ns", res.Namespace)
	assert.Equal(t, 1, res.TotalWorkloads)
	assert.Equal(t, 1, res.TotalConfigMaps)
	assert.Equal(t, 0, res.FindingsCount)
	assert.Empty(t, res.Findings)
	assert.NotNil(t, res.Findings)
	assert.Contains(t, toolResultText(t, result), `"findings":[]`)
}

func TestDetectSecretExposure_ExtendedCredentialEnvNames(t *testing.T) {
	dep := testSecretDeployment("ext-ns", "creds-app", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{"name": "DOCKER_AUTH_CONFIG", "value": `{"auths":{"registry":{"auth":"secret"}}}`},
				map[string]any{"name": "PGPASSWORD", "value": "postgresPass123"},
				map[string]any{"name": "MYSQL_PWD", "value": "mysqlPass123"},
				map[string]any{"name": "CREDENTIALS", "value": "plainCredentialsVal"},
				map[string]any{"name": "SSH_AUTH_SOCK", "value": "authSockTokenSecret"},
				map[string]any{"name": "APP_JWT", "value": "arbitraryJwtSecretStr"},
				map[string]any{"name": "AUTH_BEARER", "value": "arbitraryBearerToken"},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, dep)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "ext-ns",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	assert.Equal(t, 7, res.FindingsCount)
	matchedKeys := make(map[string]bool)
	for _, f := range res.Findings {
		matchedKeys[f.Key] = true
		assert.Equal(t, "ENV_CREDENTIAL_KEYWORD", f.RuleID)
	}
	assert.True(t, matchedKeys["DOCKER_AUTH_CONFIG"])
	assert.True(t, matchedKeys["PGPASSWORD"])
	assert.True(t, matchedKeys["MYSQL_PWD"])
	assert.True(t, matchedKeys["CREDENTIALS"])
	assert.True(t, matchedKeys["SSH_AUTH_SOCK"])
	assert.True(t, matchedKeys["APP_JWT"])
	assert.True(t, matchedKeys["AUTH_BEARER"])
}

func TestDetectSecretExposure_Filtering(t *testing.T) {
	dep1 := testSecretDeployment("filter-ns", "app-1", []map[string]any{
		{"name": "c1", "env": []any{map[string]any{"name": "API_TOKEN", "value": testGhToken("app1")}}},
	})
	dep2 := testSecretDeployment("filter-ns", "app-2", []map[string]any{
		{"name": "c2", "env": []any{map[string]any{"name": "API_TOKEN", "value": testGhToken("app2")}}},
	})
	cm := testSecretConfigMap("filter-ns", "config-1", map[string]string{
		"API_KEY": testGhToken("cm1"),
	})

	ksServer := newSecretExposureTestServer(t, dep1, dep2, cm)

	// Filter by kind: ConfigMap
	resCM := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "filter-ns",
		"resource_kind": "ConfigMap",
	}))
	require.False(t, resCM.IsError)
	var cmResult SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resCM)), &cmResult))
	assert.Equal(t, 0, cmResult.TotalWorkloads)
	assert.Equal(t, 1, cmResult.TotalConfigMaps)
	assert.Equal(t, 1, cmResult.FindingsCount)
	assert.Equal(t, "ConfigMap", cmResult.Findings[0].ResourceKind)

	// Filter by resource_name: app-1
	resName := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "filter-ns",
		"resource_name": "app-1",
	}))
	require.False(t, resName.IsError)
	var nameResult SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resName)), &nameResult))
	assert.Equal(t, 1, nameResult.TotalWorkloads)
	assert.Equal(t, 1, nameResult.FindingsCount)
	assert.Equal(t, "app-1", nameResult.Findings[0].ResourceName)
}

func TestDetectSecretExposure_ErrorsAndValidation(t *testing.T) {
	ksServer := newSecretExposureTestServer(t)

	// Missing namespace
	missingNS := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{}))
	require.True(t, missingNS.IsError)
	assert.Contains(t, toolResultText(t, missingNS), "INVALID_ARGUMENT")

	// Invalid resource_kind
	invalidKind := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "prod",
		"resource_kind": "UnknownKind",
	}))
	require.True(t, invalidKind.IsError)
	assert.Contains(t, toolResultText(t, invalidKind), "INVALID_ARGUMENT")

	// Resource not found
	notFound := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "prod",
		"resource_name": "non-existent-app",
	}))
	require.True(t, notFound.IsError)
	assert.Contains(t, toolResultText(t, notFound), "RESOURCE_NOT_FOUND")
}

func TestDetectSecretExposure_AliasTool(t *testing.T) {
	dep := testSecretDeployment("alias-ns", "web", []map[string]any{
		{
			"name": "c",
			"env": []any{
				map[string]any{"name": "API_KEY", "value": testGhToken("alias")},
			},
		},
	})
	ksServer := newSecretExposureTestServer(t, dep)

	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "analyze_secret_exposure", map[string]any{
		"namespace": "alias-ns",
	}))
	require.False(t, res.IsError)
	var parsed SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &parsed))
	assert.Equal(t, 1, parsed.FindingsCount)
}

func TestDetectSecretExposure_ForbiddenConfigMapOnWorkloadScanContinues(t *testing.T) {
	dep := testSecretDeployment("prod", "web-api", []map[string]any{
		{
			"name": "api-server",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "super" + "SecretPassword123!",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, dep)
	dyn, ok := ksServer.k8sClient.DynamicClient.(*dynamicfake.FakeDynamicClient)
	require.True(t, ok)
	dyn.PrependReactor("list", "configmaps", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "", errors.New("forbidden"))
	})

	// 1. Scoped to Deployment -> should succeed and find the Deployment's secret
	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "prod",
		"resource_kind": "Deployment",
	}))
	require.False(t, res.IsError)
	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resData))
	assert.Equal(t, 1, resData.FindingsCount)
	assert.Equal(t, "Deployment", resData.Findings[0].ResourceKind)
	assert.False(t, resData.ConfigMapReferencesResolved, "ConfigMapReferencesResolved should be false when ConfigMap list is forbidden")
	require.NotEmpty(t, resData.Warnings, "warnings must be populated when ConfigMap reference resolution fails")
	assert.Contains(t, resData.Warnings[0], "references could not be resolved")

	// 2. Unscoped or ConfigMap scoped -> should return RBAC_DENIED tool error
	resUnscoped := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "prod",
	}))
	require.True(t, resUnscoped.IsError)
	assert.Contains(t, toolResultText(t, resUnscoped), "RBAC_DENIED")
}

func TestDetectSecretExposure_ConfigFileCredentialMasking(t *testing.T) {
	// ConfigMap .env with short credential at the end of a longer file
	cmEnd := testSecretConfigMap("config-test", "cm-cred-at-end", map[string]string{
		".env": "APP_NAME=demonstration\nPASSWORD=q7!",
	})
	// ConfigMap .env with short credential at the beginning of a longer file
	cmStart := testSecretConfigMap("config-test", "cm-cred-at-start", map[string]string{
		".env": "PASSWORD=q7!\nAPP_NAME=demonstration",
	})

	ksServer := newSecretExposureTestServer(t, cmEnd, cmStart)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "config-test",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))
	assert.Equal(t, 2, res.FindingsCount)

	for _, f := range res.Findings {
		assert.Equal(t, "ConfigMap", f.ResourceKind)
		assert.Equal(t, "CONFIGMAP_SENSITIVE_KEY", f.RuleID)
		assert.Equal(t, "******", f.MaskedValue)
		assert.NotContains(t, f.MaskedValue, "q7!")
		assert.NotContains(t, f.MaskedValue, "APP_")
		assert.NotContains(t, f.MaskedValue, "PASS")
	}
}

func TestDetectSecretExposure_ReferencedConfigMapFilterByName(t *testing.T) {
	// Deployment "app" references ConfigMap "app-config" containing plaintext credential.
	cm := testSecretConfigMap("filter-ref-ns", "app-config", map[string]string{
		"DB_PASSWORD": testPassword(),
	})
	dep := testSecretDeployment("filter-ref-ns", "app", []map[string]any{
		{
			"name": "app-container",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "app-config",
					},
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cm, dep)

	// 1. Name + kind filter: resource_name="app", resource_kind="Deployment"
	resNameAndKind := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "filter-ref-ns",
		"resource_name": "app",
		"resource_kind": "Deployment",
	}))
	require.False(t, resNameAndKind.IsError)
	var dataNameAndKind SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resNameAndKind)), &dataNameAndKind))
	assert.Equal(t, 1, dataNameAndKind.TotalWorkloads)
	assert.Equal(t, 0, dataNameAndKind.TotalConfigMaps)
	assert.Equal(t, 1, dataNameAndKind.FindingsCount)
	assert.True(t, dataNameAndKind.ConfigMapReferencesResolved)
	require.Len(t, dataNameAndKind.Findings, 1)
	assert.Equal(t, "Deployment", dataNameAndKind.Findings[0].ResourceKind)
	assert.Equal(t, "app", dataNameAndKind.Findings[0].ResourceName)
	assert.Equal(t, "ENVFROM_EXPOSED_CONFIGMAP", dataNameAndKind.Findings[0].RuleID)

	// 2. Name-only filter: resource_name="app", no resource_kind
	resNameOnly := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "filter-ref-ns",
		"resource_name": "app",
	}))
	require.False(t, resNameOnly.IsError)
	var dataNameOnly SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resNameOnly)), &dataNameOnly))
	assert.Equal(t, 1, dataNameOnly.TotalWorkloads)
	assert.Equal(t, 0, dataNameOnly.TotalConfigMaps)
	assert.Equal(t, 1, dataNameOnly.FindingsCount)
	assert.True(t, dataNameOnly.ConfigMapReferencesResolved)
	require.Len(t, dataNameOnly.Findings, 1)
	assert.Equal(t, "Deployment", dataNameOnly.Findings[0].ResourceKind)
	assert.Equal(t, "app", dataNameOnly.Findings[0].ResourceName)
	assert.Equal(t, "ENVFROM_EXPOSED_CONFIGMAP", dataNameOnly.Findings[0].RuleID)
}

func TestDetectSecretExposure_CredentialStartingWithSlash(t *testing.T) {
	dep := testSecretDeployment("slash-ns", "app", []map[string]any{
		{
			"name": "c",
			"env": []any{
				map[string]any{"name": "DB_PASSWORD", "value": "/aB3xY9SecretPass!"},
				map[string]any{"name": "SECRET_KEY", "value": "/custom/secret/value"},
				map[string]any{"name": "APP_PWD", "value": "/workspace"},
				map[string]any{"name": "PWD", "value": "/app"},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, dep)
	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "slash-ns",
	}))
	require.False(t, res.IsError)

	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resData))
	assert.Equal(t, 2, resData.FindingsCount)

	keys := make(map[string]bool)
	for _, f := range resData.Findings {
		keys[f.Key] = true
		assert.Equal(t, "ENV_CREDENTIAL_KEYWORD", f.RuleID)
	}
	assert.True(t, keys["DB_PASSWORD"])
	assert.True(t, keys["SECRET_KEY"])
	assert.False(t, keys["APP_PWD"])
	assert.False(t, keys["PWD"])
}

func TestDetectSecretExposure_CompoundCredentialMasking(t *testing.T) {
	// Database URL with password in query parameter
	podWithURL := testSecretPod("compound-test", "pod-url", []map[string]any{
		{
			"name": "app",
			"env": []any{
				map[string]any{
					"name":  "DATABASE_URL",
					"value": "postgres://dbadmin@db.internal/app?password=q7!",
				},
				map[string]any{
					"name":  "DIRECT_URL",
					"value": testDatabaseURL(),
				},
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "Server=127.0.0.1;Database=test;Uid=admin;Pwd=supersecretpassword123!;",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, podWithURL)
	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "compound-test",
	}))
	require.False(t, res.IsError)

	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resData))
	assert.Equal(t, 3, resData.FindingsCount)

	for _, f := range resData.Findings {
		assert.Equal(t, "******", f.MaskedValue)
		assert.NotContains(t, f.MaskedValue, "q7!")
		assert.NotContains(t, f.MaskedValue, "post****=q7!")
		assert.NotContains(t, f.MaskedValue, "TopSecretPass123")
		assert.NotContains(t, f.MaskedValue, "supersecretpassword123!")
	}
}

func TestDetectSecretExposure_LivePodsDeduplication_CleanStatefulSet(t *testing.T) {
	// Clean StatefulSet with no exposed environment variables
	ss := testSecretStatefulSet("live-test", "my-statefulset", []map[string]any{
		{
			"name":  "main",
			"image": "nginx",
		},
	})
	ss.SetUID("ss-uid-100")

	// Owned Pod with DB_PASSWORD (e.g. injected or differed in live cluster)
	pod := testSecretPod("live-test", "my-statefulset-0", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": testPassword(),
				},
			},
		},
	})
	pod.SetUID("pod-uid-100")
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"name":       "my-statefulset",
			"uid":        "ss-uid-100",
			"controller": true,
		},
	}

	ksServer := newSecretExposureTestServer(t, ss, pod)

	// 1. Pod-only scan finds the exposed secret on the Pod
	resPod := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "live-test",
		"resource_kind": "Pod",
	}))
	require.False(t, resPod.IsError)
	var resPodData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resPod)), &resPodData))
	assert.Equal(t, 1, resPodData.FindingsCount)
	assert.Equal(t, "Pod", resPodData.Findings[0].ResourceKind)
	assert.Equal(t, "my-statefulset-0", resPodData.Findings[0].ResourceName)
	assert.Equal(t, "DB_PASSWORD", resPodData.Findings[0].Key)

	// 2. Namespace scan also retains the finding on the live Pod even though its controller is present
	resNS := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "live-test",
	}))
	require.False(t, resNS.IsError)
	var resNSData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resNS)), &resNSData))
	assert.Equal(t, 1, resNSData.FindingsCount)
	assert.Equal(t, "Pod", resNSData.Findings[0].ResourceKind)
	assert.Equal(t, "my-statefulset-0", resNSData.Findings[0].ResourceName)
	assert.Equal(t, "DB_PASSWORD", resNSData.Findings[0].Key)
}

func TestDetectSecretExposure_LivePodsDeduplication_InheritedSecretSuppressed(t *testing.T) {
	// StatefulSet containing DB_PASSWORD in template
	ss := testSecretStatefulSet("dedup-test", "my-statefulset", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": testPassword(),
				},
			},
		},
	})
	ss.SetUID("ss-uid-200")

	// Owned Pod with matching DB_PASSWORD inherited from the StatefulSet
	pod := testSecretPod("dedup-test", "my-statefulset-0", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": testPassword(),
				},
			},
		},
	})
	pod.SetUID("pod-uid-200")
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"name":       "my-statefulset",
			"uid":        "ss-uid-200",
			"controller": true,
		},
	}

	ksServer := newSecretExposureTestServer(t, ss, pod)

	resNS := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "dedup-test",
	}))
	require.False(t, resNS.IsError)
	var resNSData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resNS)), &resNSData))

	// Finding is deduplicated to the StatefulSet controller; the owned Pod does not produce a duplicate finding
	assert.Equal(t, 1, resNSData.FindingsCount)
	assert.Equal(t, "StatefulSet", resNSData.Findings[0].ResourceKind)
	assert.Equal(t, "my-statefulset", resNSData.Findings[0].ResourceName)
	assert.Equal(t, "DB_PASSWORD", resNSData.Findings[0].Key)
}

func TestDetectSecretExposure_LivePodsDeduplication_ExtraSecretOnPod(t *testing.T) {
	// StatefulSet containing DB_PASSWORD
	ss := testSecretStatefulSet("extra-test", "my-statefulset", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": testPassword(),
				},
			},
		},
	})
	ss.SetUID("ss-uid-300")

	// Owned Pod containing DB_PASSWORD AND an extra secret (API_KEY)
	pod := testSecretPod("extra-test", "my-statefulset-0", []map[string]any{
		{
			"name": "main",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": testPassword(),
				},
				map[string]any{
					"name":  "API_KEY",
					"value": "custom-secret-key-12345",
				},
			},
		},
	})
	pod.SetUID("pod-uid-300")
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"name":       "my-statefulset",
			"uid":        "ss-uid-300",
			"controller": true,
		},
	}

	ksServer := newSecretExposureTestServer(t, ss, pod)

	resNS := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "extra-test",
	}))
	require.False(t, resNS.IsError)
	var resNSData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resNS)), &resNSData))

	// DB_PASSWORD is on StatefulSet, API_KEY is on Pod (DB_PASSWORD on Pod was suppressed)
	assert.Equal(t, 2, resNSData.FindingsCount)
	foundSS := false
	foundPod := false
	for _, f := range resNSData.Findings {
		if f.ResourceKind == "StatefulSet" && f.Key == "DB_PASSWORD" {
			foundSS = true
		}
		if f.ResourceKind == "Pod" && f.Key == "API_KEY" {
			foundPod = true
		}
	}
	assert.True(t, foundSS)
	assert.True(t, foundPod)
}

func TestDetectSecretExposure_Deduplication_DifferentSecretValueNotDeduplicated(t *testing.T) {
	// Scenario: Deployment rotates DB_PASSWORD, but an older ReplicaSet is still running
	// with the previous DB_PASSWORD. Even though Container, Location, and Key match,
	// deduplication must NOT suppress the ReplicaSet finding because the raw values differ.
	// However, a Pod owned by the ReplicaSet with the identical old password MUST be deduplicated.
	deploy := testSecretDeployment("rot-test", "api-deploy", []map[string]any{
		{
			"name": "api",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "NewRotatedPassword123!",
				},
			},
		},
	})
	deploy.SetUID("deploy-uid-100")

	rs := testSecretReplicaSet("rot-test", "api-deploy-old-rs", []map[string]any{
		{
			"name": "api",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "OldPreviousPassword999!",
				},
			},
		},
	})
	rs.SetUID("rs-uid-100")
	rs.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"name":       "api-deploy",
			"uid":        "deploy-uid-100",
			"controller": true,
		},
	}

	pod := testSecretPod("rot-test", "api-deploy-old-rs-pod", []map[string]any{
		{
			"name": "api",
			"env": []any{
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "OldPreviousPassword999!",
				},
			},
		},
	})
	pod.SetUID("pod-uid-100")
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "ReplicaSet",
			"name":       "api-deploy-old-rs",
			"uid":        "rs-uid-100",
			"controller": true,
		},
	}

	ksServer := newSecretExposureTestServer(t, deploy, rs, pod)

	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "rot-test",
	}))
	require.False(t, res.IsError)
	rawJSON := toolResultText(t, res)

	// Verify internal valueDigest is not leaked into JSON
	assert.NotContains(t, rawJSON, "valueDigest")

	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(rawJSON), &resData))

	// Deployment finding and ReplicaSet finding are both reported (different passwords),
	// but Pod finding is deduplicated into the ReplicaSet (same password).
	require.Equal(t, 2, resData.FindingsCount)

	foundDeploy := false
	foundRS := false
	for _, f := range resData.Findings {
		if f.ResourceKind == "Deployment" && f.ResourceName == "api-deploy" {
			foundDeploy = true
		}
		if f.ResourceKind == "ReplicaSet" && f.ResourceName == "api-deploy-old-rs" {
			foundRS = true
		}
	}
	assert.True(t, foundDeploy, "Deployment finding should be reported")
	assert.True(t, foundRS, "Old ReplicaSet finding with different credential should not be deduplicated")
}

func TestDetectSecretExposure_PrefixedEnvFromConfigMap(t *testing.T) {
	// ConfigMap with non-sensitive key name that becomes sensitive when prefixed
	cm := testSecretConfigMap("prefix-test", "prefixed-cm", map[string]string{
		"KEY": "opaqueCredentialValue987!",
	})

	// Pod importing via envFrom with prefix "API_" -> effectively "API_KEY"
	podPrefixed := testSecretPod("prefix-test", "prefixed-consumer", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"prefix": "API_",
					"configMapRef": map[string]any{
						"name": "prefixed-cm",
					},
				},
			},
		},
	})

	// Direct Pod with explicit env API_KEY
	podDirect := testSecretPod("prefix-test", "direct-consumer", []map[string]any{
		{
			"name": "worker",
			"env": []any{
				map[string]any{
					"name":  "API_KEY",
					"value": "opaqueCredentialValue987!",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cm, podPrefixed, podDirect)

	// 1. ConfigMap alone has zero findings since "KEY" is not a sensitive keyword
	resCM := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "prefix-test",
		"resource_kind": "ConfigMap",
	}))
	require.False(t, resCM.IsError)
	var resCMData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resCM)), &resCMData))
	assert.Equal(t, 0, resCMData.FindingsCount)

	// 2. Direct Pod scan finds API_KEY
	resDirect := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "prefix-test",
		"resource_kind": "Pod",
		"resource_name": "direct-consumer",
	}))
	require.False(t, resDirect.IsError)
	var resDirectData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resDirect)), &resDirectData))
	require.Equal(t, 1, resDirectData.FindingsCount)
	assert.Equal(t, "API_KEY", resDirectData.Findings[0].Key)
	assert.Equal(t, "ENV_CREDENTIAL_KEYWORD", resDirectData.Findings[0].RuleID)
	assert.Equal(t, "opaq****987!", resDirectData.Findings[0].MaskedValue)

	// 3. Prefixed envFrom scan evaluates effective name (prefix + key = API_KEY)
	resPrefixed := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "prefix-test",
		"resource_kind": "Pod",
		"resource_name": "prefixed-consumer",
	}))
	require.False(t, resPrefixed.IsError)
	var resPrefixedData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resPrefixed)), &resPrefixedData))
	require.Equal(t, 1, resPrefixedData.FindingsCount)
	assert.Equal(t, "prefixed-cm", resPrefixedData.Findings[0].Key)
	assert.Equal(t, "ENVFROM_EXPOSED_CONFIGMAP", resPrefixedData.Findings[0].RuleID)
	// Masked preview should match the direct credential masking
	assert.Equal(t, resDirectData.Findings[0].MaskedValue, resPrefixedData.Findings[0].MaskedValue)
}

func TestDetectSecretExposure_MixedTemplateAndCredentials(t *testing.T) {
	// Mixed template with concrete URI credentials
	cmMixedURI := testSecretConfigMap("template-test", "mixed-uri-cm", map[string]string{
		"app.conf": "GREETING={{ .Greeting }}\nURL=" + testDatabaseURL(),
	})
	// Mixed template with concrete AWS key credential
	cmMixedKey := testSecretConfigMap("template-test", "mixed-key-cm", map[string]string{
		"app.conf": "GREETING={{ .Greeting }}\nAWS_KEY=" + testAwsKey(),
	})
	// Pure template ConfigMaps
	cmPureSingle := testSecretConfigMap("template-test", "pure-single-cm", map[string]string{
		"app.conf": "{{ .Greeting }}",
	})
	cmPureMulti := testSecretConfigMap("template-test", "pure-multi-cm", map[string]string{
		"app.conf": "GREETING={{ .Greeting }}\nTITLE={{ .Title }}",
	})

	// Pod with pure placeholder expressions in env
	podPure := testSecretPod("template-test", "pure-template-pod", []map[string]any{
		{
			"name": "worker",
			"env": []any{
				map[string]any{"name": "DB_PASSWORD", "value": "{{ .Values.dbPassword }}"},
				map[string]any{"name": "API_KEY", "value": "$(DYNAMIC_KEY)"},
				map[string]any{"name": "SECRET_TOKEN", "value": "${DYNAMIC_TOKEN}"},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cmMixedURI, cmMixedKey, cmPureSingle, cmPureMulti, podPure)

	// 1. Mixed URI credentials detected
	resURI := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "template-test",
		"resource_kind": "ConfigMap",
		"resource_name": "mixed-uri-cm",
	}))
	require.False(t, resURI.IsError)
	var resURIData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resURI)), &resURIData))
	require.Equal(t, 1, resURIData.FindingsCount)
	assert.Equal(t, "URI_CREDENTIALS", resURIData.Findings[0].RuleID)
	assert.Equal(t, "******", resURIData.Findings[0].MaskedValue)
	assert.NotContains(t, resURIData.Findings[0].MaskedValue, "TopSecretPass123")

	// 2. Mixed token credential detected
	resKey := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "template-test",
		"resource_kind": "ConfigMap",
		"resource_name": "mixed-key-cm",
	}))
	require.False(t, resKey.IsError)
	var resKeyData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resKey)), &resKeyData))
	require.Equal(t, 1, resKeyData.FindingsCount)
	assert.Equal(t, "AWS_ACCESS_KEY_ID", resKeyData.Findings[0].RuleID)

	// 3. Pure single-line template ConfigMap has zero findings
	resPureSingle := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "template-test",
		"resource_kind": "ConfigMap",
		"resource_name": "pure-single-cm",
	}))
	require.False(t, resPureSingle.IsError)
	var resPureSingleData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resPureSingle)), &resPureSingleData))
	assert.Equal(t, 0, resPureSingleData.FindingsCount)

	// 4. Pure multiline template ConfigMap has zero findings
	resPureMulti := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "template-test",
		"resource_kind": "ConfigMap",
		"resource_name": "pure-multi-cm",
	}))
	require.False(t, resPureMulti.IsError)
	var resPureMultiData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resPureMulti)), &resPureMultiData))
	assert.Equal(t, 0, resPureMultiData.FindingsCount)

	// 5. Pure template expressions in Pod environment have zero findings
	resPod := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "template-test",
		"resource_kind": "Pod",
		"resource_name": "pure-template-pod",
	}))
	require.False(t, resPod.IsError)
	var resPodData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resPod)), &resPodData))
	assert.Equal(t, 0, resPodData.FindingsCount)
}

func TestDetectSecretExposure_SingleLinePlaceholderWithLiteralCredential(t *testing.T) {
	// A single-line value that mixes literal credentials between dynamic placeholders
	// (e.g. ${PREFIX}AKIA...${SUFFIX} or $(DB_USER):Password@$(DB_HOST)) must be flagged
	// and not treated as a safe single placeholder expression.
	podMixed := testSecretPod("single-placeholder-test", "mixed-single-line-pod", []map[string]any{
		{
			"name": "worker",
			"env": []any{
				map[string]any{
					"name":  "AWS_COMPOSED_KEY",
					"value": "${PREFIX}" + testAwsKey() + "${SUFFIX}",
				},
				map[string]any{
					"name":  "DB_COMPOSED_URL",
					"value": "postgres://$(DB_USER):" + "SuperSecretPass123!" + "@$(DB_HOST):5432/db",
				},
				map[string]any{
					"name":  "GITHUB_COMPOSED_TOKEN",
					"value": "{{ .Prefix }}" + testGhToken("token") + "{{ .Suffix }}",
				},
				// Pure single placeholder expressions must remain safe/suppressed
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "$(PURE_DYNAMIC_PASSWORD)",
				},
				map[string]any{
					"name":  "API_KEY",
					"value": "${PURE_DYNAMIC_KEY}",
				},
				map[string]any{
					"name":  "SECRET_TOKEN",
					"value": "{{ .Values.pureToken }}",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, podMixed)

	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "single-placeholder-test",
		"resource_kind": "Pod",
		"resource_name": "mixed-single-line-pod",
	}))
	require.False(t, res.IsError)
	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resData))

	// The three mixed compositions should be detected, and the three pure placeholders ignored
	assert.Equal(t, 3, resData.FindingsCount)
	foundAWS := false
	foundDB := false
	foundGH := false
	for _, f := range resData.Findings {
		if f.Key == "AWS_COMPOSED_KEY" {
			foundAWS = true
			assert.Equal(t, "AWS_ACCESS_KEY_ID", f.RuleID)
		}
		if f.Key == "DB_COMPOSED_URL" {
			foundDB = true
		}
		if f.Key == "GITHUB_COMPOSED_TOKEN" {
			foundGH = true
			assert.Equal(t, "GITHUB_TOKEN", f.RuleID)
		}
	}
	assert.True(t, foundAWS, "AWS access key between placeholders must be detected")
	assert.True(t, foundDB, "URI credentials composition between placeholders must be detected")
	assert.True(t, foundGH, "GitHub token between template tags must be detected")
}

func TestIsCompletePlaceholderExpression(t *testing.T) {
	// Valid single placeholder expressions
	assert.True(t, isCompletePlaceholderExpression("$(VAR)"))
	assert.True(t, isCompletePlaceholderExpression("${VAR}"))
	assert.True(t, isCompletePlaceholderExpression("{{ .Values.secret }}"))
	assert.True(t, isCompletePlaceholderExpression("   $(WHITESPACE_TRIMMED)   "))
	assert.True(t, isCompletePlaceholderExpression("{{- .Values.secret -}}"))
	assert.True(t, isCompletePlaceholderExpression("{{ $dynamicVar }}"))

	// Multiple placeholders on a single line
	assert.False(t, isCompletePlaceholderExpression("${PREFIX}literal${SUFFIX}"))
	assert.False(t, isCompletePlaceholderExpression("$(USER):pass@$(HOST)"))
	assert.False(t, isCompletePlaceholderExpression("{{ .A }}{{ .B }}"))
	assert.False(t, isCompletePlaceholderExpression("$(VAR1)$(VAR2)"))

	// Expressions with defaults, commands, or literals
	assert.False(t, isCompletePlaceholderExpression("${DB_PASSWORD:-MyPlainPass99}"))
	assert.False(t, isCompletePlaceholderExpression("${VAR:=default}"))
	assert.False(t, isCompletePlaceholderExpression("$(echo plain_secret)"))
	assert.False(t, isCompletePlaceholderExpression("{{ \"literal\" }}"))

	// Multiline strings
	assert.False(t, isCompletePlaceholderExpression("$(VAR)\n$(VAR2)"))
	assert.False(t, isCompletePlaceholderExpression("${VAR}\r\n${VAR2}"))

	// Partial or trailing text
	assert.False(t, isCompletePlaceholderExpression("$(VAR)trailing"))
	assert.False(t, isCompletePlaceholderExpression("leading$(VAR)"))
	assert.False(t, isCompletePlaceholderExpression("$(VAR1)trailing)paren"))
}

func TestDetectSecretExposure_WorkloadEnvFromConfigMap_ExplicitEnvOverride(t *testing.T) {
	cm := testSecretConfigMap("staging", "creds-cm", map[string]string{
		"DB_PASSWORD": testPassword(),
	})

	overriddenPod := testSecretPod("staging", "overridden-pod", []map[string]any{
		{
			"name": "app",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "creds-cm",
					},
				},
			},
			"env": []any{
				map[string]any{
					"name": "DB_PASSWORD",
					"valueFrom": map[string]any{
						"secret" + "KeyRef": map[string]any{
							"name": "vault-" + "secret",
							"key":  "pass" + "word",
						},
					},
				},
			},
		},
	})

	unoverriddenPod := testSecretPod("staging", "unoverridden-pod", []map[string]any{
		{
			"name": "app",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "creds-cm",
					},
				},
			},
			"env": []any{
				map[string]any{
					"name":  "PORT",
					"value": "8080",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cm, overriddenPod, unoverriddenPod)

	// 1. Pod-only scan: overridden-pod should NOT report ENVFROM_EXPOSED_CONFIGMAP
	podScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "staging",
		"resource_kind": "Pod",
	}))
	require.False(t, podScanResult.IsError)

	var podRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, podScanResult)), &podRes))

	for _, f := range podRes.Findings {
		assert.NotEqual(t, "overridden-pod", f.ResourceName, "overridden key must not produce workload finding")
	}

	var hasUnoverriddenFinding bool
	for _, f := range podRes.Findings {
		if f.ResourceName == "unoverridden-pod" && f.RuleID == "ENVFROM_EXPOSED_CONFIGMAP" {
			hasUnoverriddenFinding = true
		}
	}
	assert.True(t, hasUnoverriddenFinding, "unoverridden pod should still report ENVFROM_EXPOSED_CONFIGMAP")

	// 2. Namespace scan: ConfigMap itself is flagged, but overridden-pod remains clean
	nsScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "staging",
	}))
	require.False(t, nsScanResult.IsError)

	var nsRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, nsScanResult)), &nsRes))

	var cmFlagged bool
	for _, f := range nsRes.Findings {
		assert.NotEqual(t, "overridden-pod", f.ResourceName, "overridden-pod must not be flagged in namespace scan")
		if f.ResourceKind == "ConfigMap" && f.ResourceName == "creds-cm" {
			cmFlagged = true
		}
	}
	assert.True(t, cmFlagged, "ConfigMap itself must still be flagged in namespace scan")
}

func TestDetectSecretExposure_ConfigMapBinaryData_Masking(t *testing.T) {
	cm := testSecretConfigMapWithBinaryData("default", "binary-creds", nil, map[string]string{
		"DB_PASS" + "WORD": "TXlT" + "M3JldFBhc3N3MHJkIQ==",
	})

	ksServer := newSecretExposureTestServer(t, cm)
	result := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "default",
	}))
	require.False(t, result.IsError)

	var res SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, result)), &res))

	require.Equal(t, 1, res.FindingsCount)
	f := res.Findings[0]
	assert.Equal(t, "ConfigMap", f.ResourceKind)
	assert.Equal(t, "binaryData.DB_PASSWORD", f.Location)
	assert.Equal(t, "******", f.MaskedValue, "binaryData findings must be fully redacted as ******")
}

func TestDetectSecretExposure_PlaceholderWithLiteralCredential_DefaultSyntax(t *testing.T) {
	pod := testSecretPod("default-syntax-test", "pod-syntax", []map[string]any{
		{
			"name": "app",
			"env": []any{
				map[string]any{
					"name":  "NON_SENSITIVE_APP_KEY",
					"value": "${CONFIG_OPT:-" + testAwsKey() + "}",
				},
				map[string]any{
					"name":  "NON_SENSITIVE_RUN_CMD",
					"value": "$(echo " + testGhToken("cmdecho") + ")",
				},
				// Opaque default password inside ${...:-...} under sensitive key name must produce ENV_CREDENTIAL_KEYWORD
				map[string]any{
					"name":  "DB_PASSWORD",
					"value": "${DB_PASSWORD:-" + "Opaque" + "Pass" + "word99!" + "}",
				},
				// Pure bare variable reference under sensitive key name must remain safe
				map[string]any{
					"name":  "SAFE_DYNAMIC_PASSWORD",
					"value": "${SAFE_DYNAMIC_PASSWORD}",
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, pod)
	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "default-syntax-test",
		"resource_kind": "Pod",
	}))
	require.False(t, res.IsError)

	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resData))

	assert.Equal(t, 3, resData.FindingsCount)
	foundAWS := false
	foundGH := false
	foundOpaqueDefault := false
	for _, f := range resData.Findings {
		if f.Key == "NON_SENSITIVE_APP_KEY" {
			foundAWS = true
			assert.Equal(t, "AWS_ACCESS_KEY_ID", f.RuleID)
		}
		if f.Key == "NON_SENSITIVE_RUN_CMD" {
			foundGH = true
			assert.Equal(t, "GITHUB_TOKEN", f.RuleID)
		}
		if f.Key == "DB_PASSWORD" {
			foundOpaqueDefault = true
			assert.Equal(t, "ENV_CREDENTIAL_KEYWORD", f.RuleID)
			assert.Equal(t, "High", f.Severity)
		}
		assert.NotEqual(t, "SAFE_DYNAMIC_PASSWORD", f.Key, "pure bare variable reference under sensitive key must remain safe")
	}
	assert.True(t, foundAWS, "literal AWS key inside ${VAR:-default} under non-sensitive key must be detected")
	assert.True(t, foundGH, "literal GitHub token inside $(echo ...) under non-sensitive key must be detected")
	assert.True(t, foundOpaqueDefault, "opaque default credential inside ${DB_PASSWORD:-...} under sensitive key must be detected as ENV_CREDENTIAL_KEYWORD")
}

func TestDetectSecretExposure_SingleLineYAMLMask(t *testing.T) {
	cm := testSecretConfigMap("single-line-yaml", "app-config", map[string]string{
		"AUTH_CONFIG": "database_" + "password: " + "q7!",
		"DB_PASSWORD": "pass" + "word=" + "q7!" + "andmorechars",
	})

	ksServer := newSecretExposureTestServer(t, cm)
	res := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "single-line-yaml",
	}))
	require.False(t, res.IsError)

	var resData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, res)), &resData))
	require.Equal(t, 2, resData.FindingsCount)

	for _, f := range resData.Findings {
		assert.Equal(t, "******", f.MaskedValue, "single-line YAML and single-assignment values must be fully redacted")
		assert.NotContains(t, f.MaskedValue, "q7!")
	}
}

func TestDetectSecretExposure_EnvFromDedupDistinctExposure(t *testing.T) {
	cm := testSecretConfigMap("stale-pod-test", "app-cm", map[string]string{
		"A_PASSWORD": "common" + "Credential" + "987!",
		"Z_PASSWORD": "stale" + "Credential" + "987!",
	})

	ss := testSecretStatefulSet("stale-pod-test", "my-ss", []map[string]any{
		{
			"name": "main",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "app-cm",
					},
				},
			},
			"env": []any{
				map[string]any{
					"name": "Z_PASSWORD",
					"valueFrom": map[string]any{
						"secret" + "KeyRef": map[string]any{
							"name": "vault-" + "secret",
							"key":  "pass" + "word",
						},
					},
				},
			},
		},
	})
	ss.SetUID("ss-uid-500")

	pod := testSecretPod("stale-pod-test", "my-ss-0", []map[string]any{
		{
			"name": "main",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "app-cm",
					},
				},
			},
		},
	})
	pod.SetUID("pod-uid-500")
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"name":       "my-ss",
			"uid":        "ss-uid-500",
			"controller": true,
		},
	}

	ksServer := newSecretExposureTestServer(t, cm, ss, pod)

	podScan := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "stale-pod-test",
		"resource_kind": "Pod",
	}))
	require.False(t, podScan.IsError)
	var podData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, podScan)), &podData))
	require.Equal(t, 1, podData.FindingsCount, "Pod-only scan must find 1 exposure on the stale Pod")
	assert.Equal(t, "my-ss-0", podData.Findings[0].ResourceName)

	nsScan := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "stale-pod-test",
	}))
	require.False(t, nsScan.IsError)
	var nsData SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, nsScan)), &nsData))

	var foundSS, foundPod bool
	for _, f := range nsData.Findings {
		if f.ResourceKind == "StatefulSet" && f.ResourceName == "my-ss" {
			foundSS = true
		}
		if f.ResourceKind == "Pod" && f.ResourceName == "my-ss-0" {
			foundPod = true
		}
	}
	assert.True(t, foundSS, "StatefulSet finding must be present in namespace scan")
	assert.True(t, foundPod, "stale Pod finding must NOT be deduplicated away because it exposes additional credential Z_PASSWORD")
}

func TestDetectSecretExposure_EnvFromSourcePrecedence(t *testing.T) {
	// Original ConfigMap contains a sensitive credential
	cmOriginal := testSecretConfigMap("precedence-test", "original", map[string]string{
		"DB_PASSWORD": testPassword(),
	})

	// Override ConfigMap contains a non-sensitive override for the same key
	cmOverride := testSecretConfigMap("precedence-test", "override", map[string]string{
		"DB_PASSWORD": "dis" + "abled",
	})

	// Pod imports original followed by override. The later envFrom source takes precedence in Kubernetes.
	podOverridden := testSecretPod("precedence-test", "precedence-pod", []map[string]any{
		{
			"name": "app",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "original",
					},
				},
				map[string]any{
					"configMapRef": map[string]any{
						"name": "override",
					},
				},
			},
		},
	})

	// Pod with prefix where later envFrom source with matching prefix overrides the key
	cmPrefixedOrig := testSecretConfigMap("precedence-test", "prefixed-orig", map[string]string{
		"SECRET": "sup" + "erSecret123!",
	})
	cmPrefixedOverride := testSecretConfigMap("precedence-test", "prefixed-override", map[string]string{
		"SECRET": "dis" + "abled",
	})
	podPrefixed := testSecretPod("precedence-test", "prefixed-pod", []map[string]any{
		{
			"name": "app",
			"envFrom": []any{
				map[string]any{
					"prefix": "APP_",
					"configMapRef": map[string]any{
						"name": "prefixed-orig",
					},
				},
				map[string]any{
					"prefix": "APP_",
					"configMapRef": map[string]any{
						"name": "prefixed-override",
					},
				},
			},
		},
	})

	// Pod where earlier source has multiple keys and only one is overridden
	cmMulti := testSecretConfigMap("precedence-test", "multi-orig", map[string]string{
		"DB_PASSWORD": testPassword(),
		"API_KEY":     "k" + "ey12345678901234567890!",
	})
	podPartial := testSecretPod("precedence-test", "partial-pod", []map[string]any{
		{
			"name": "app",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "multi-orig",
					},
				},
				map[string]any{
					"configMapRef": map[string]any{
						"name": "override",
					},
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cmOriginal, cmOverride, podOverridden, cmPrefixedOrig, cmPrefixedOverride, podPrefixed, cmMulti, podPartial)

	// 1. Pod-only scan: precedence-pod and prefixed-pod must produce 0 findings because their sensitive keys are overridden by later envFrom sources.
	// partial-pod still exposes API_KEY so it should be reported.
	podScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "precedence-test",
		"resource_kind": "Pod",
	}))
	require.False(t, podScanResult.IsError)

	var podRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, podScanResult)), &podRes))

	for _, f := range podRes.Findings {
		assert.NotEqual(t, "precedence-pod", f.ResourceName, "precedence-pod should have 0 findings as its credential is overridden by a later envFrom source")
		assert.NotEqual(t, "prefixed-pod", f.ResourceName, "prefixed-pod should have 0 findings as its prefixed credential is overridden by a later envFrom source")
	}

	var foundPartial bool
	for _, f := range podRes.Findings {
		if f.ResourceName == "partial-pod" && f.RuleID == "ENVFROM_EXPOSED_CONFIGMAP" {
			foundPartial = true
		}
	}
	assert.True(t, foundPartial, "partial-pod must still be flagged because API_KEY was not overridden")

	// 2. Specific pod scan on precedence-pod: exactly 0 findings
	specificPodResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "precedence-test",
		"resource_kind": "Pod",
		"resource_name": "precedence-pod",
	}))
	require.False(t, specificPodResult.IsError)
	var specificPodRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, specificPodResult)), &specificPodRes))
	assert.Equal(t, 0, specificPodRes.FindingsCount, "Pod-only scan on precedence-pod must return 0 findings")

	// 3. Namespace scan: original ConfigMap must still be flagged, but precedence-pod remains clean
	nsScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "precedence-test",
	}))
	require.False(t, nsScanResult.IsError)

	var nsRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, nsScanResult)), &nsRes))

	var originalCMFlagged bool
	for _, f := range nsRes.Findings {
		assert.NotEqual(t, "precedence-pod", f.ResourceName, "precedence-pod must not be flagged in namespace scan")
		if f.ResourceKind == "ConfigMap" && f.ResourceName == "original" {
			originalCMFlagged = true
		}
	}
	assert.True(t, originalCMFlagged, "original ConfigMap must still be flagged when ConfigMaps are in scope")
}

func TestDetectSecretExposure_WorkloadEnvFromConfigMap_SeverityPreservation(t *testing.T) {
	// ConfigMap containing a Critical credential (GitHub token)
	cmCritical := testSecretConfigMap("sev-test", "critical-cm", map[string]string{
		"GH_TOKEN": testGhToken("cmcrit"),
	})

	// ConfigMap containing a High credential (keyword match)
	cmHigh := testSecretConfigMap("sev-test", "high-cm", map[string]string{
		"DB_PASSWORD": testPassword(),
	})

	// Workload importing the Critical ConfigMap
	podCritical := testSecretPod("sev-test", "critical-pod", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "critical-cm",
					},
				},
			},
		},
	})

	// Workload importing the High ConfigMap
	podHigh := testSecretPod("sev-test", "high-pod", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "high-cm",
					},
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cmCritical, cmHigh, podCritical, podHigh)

	// Workload-only scan
	podScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "sev-test",
		"resource_kind": "Pod",
	}))
	require.False(t, podScanResult.IsError)

	var podRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, podScanResult)), &podRes))
	require.Equal(t, 2, podRes.FindingsCount)

	for _, f := range podRes.Findings {
		assert.Equal(t, "ENVFROM_EXPOSED_CONFIGMAP", f.RuleID)
		if f.ResourceName == "critical-pod" {
			assert.Equal(t, "Critical", f.Severity, "envFrom importing a Critical token must have Critical severity")
		}
		if f.ResourceName == "high-pod" {
			assert.Equal(t, "High", f.Severity, "envFrom importing a High credential must have High severity")
		}
	}
}

func TestDetectSecretExposure_WorkloadEnvFromConfigMap_LaterSecretRefQualification(t *testing.T) {
	cm := testSecretConfigMap("qualify-test", "app-config", map[string]string{
		"DB_PASSWORD": testPassword(),
	})

	// Pod imports app-config via configMapRef, followed by secretRef: db-secret
	pod := testSecretPod("qualify-test", "consumer-pod", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "app-config",
					},
				},
				map[string]any{
					"secretRef": map[string]any{
						"name": "db-secret",
					},
				},
			},
		},
	})

	ksServer := newSecretExposureTestServer(t, cm, pod)

	// Workload scan
	podScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "qualify-test",
		"resource_kind": "Pod",
	}))
	require.False(t, podScanResult.IsError)

	var podRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, podScanResult)), &podRes))
	require.Equal(t, 1, podRes.FindingsCount)

	f := podRes.Findings[0]
	assert.Equal(t, "ENVFROM_EXPOSED_CONFIGMAP", f.RuleID)
	assert.Equal(t, "app-config", f.Key)
	assert.Contains(t, f.Description, "later Secret sources [db-secret] may override some imported keys")

	// Namespace scan: ConfigMap finding itself is not qualified, but workload finding is
	nsScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "qualify-test",
	}))
	require.False(t, nsScanResult.IsError)

	var nsRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, nsScanResult)), &nsRes))
	require.Equal(t, 2, nsRes.FindingsCount)

	for _, finding := range nsRes.Findings {
		if finding.ResourceKind == "ConfigMap" {
			assert.NotContains(t, finding.Description, "later Secret sources")
		}
		if finding.ResourceKind == "Pod" {
			assert.Contains(t, finding.Description, "later Secret sources [db-secret] may override some imported keys")
		}
	}
}

func TestDetectSecretExposure_Deduplication_ConfirmedPodKeptWhenParentUncertain(t *testing.T) {
	cm := testSecretConfigMap("sts-dedup", "app-config", map[string]string{
		"DB_PASSWORD": testPassword(),
	})

	// Parent StatefulSet imports app-config via envFrom, followed by a later secretRef: db-secret.
	// Its finding is uncertain (qualified with later Secret sources warning).
	ss := testSecretStatefulSet("sts-dedup", "my-statefulset", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "app-config",
					},
				},
				map[string]any{
					"secretRef": map[string]any{
						"name": "db-secret",
					},
				},
			},
		},
	})
	ss.SetUID("ss-uid-400")

	// Stale child Pod owned by the StatefulSet imports app-config WITHOUT the later secretRef.
	// Its finding is confirmed (not qualified with later Secret sources warning).
	pod := testSecretPod("sts-dedup", "my-statefulset-0", []map[string]any{
		{
			"name": "worker",
			"envFrom": []any{
				map[string]any{
					"configMapRef": map[string]any{
						"name": "app-config",
					},
				},
			},
		},
	})
	pod.SetUID("pod-uid-400")
	pod.Object["metadata"].(map[string]any)["ownerReferences"] = []any{
		map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"name":       "my-statefulset",
			"uid":        "ss-uid-400",
			"controller": true,
		},
	}

	ksServer := newSecretExposureTestServer(t, cm, ss, pod)

	// 1. Scanned alone: Pod produces 1 confirmed finding
	podScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace":     "sts-dedup",
		"resource_kind": "Pod",
		"resource_name": "my-statefulset-0",
	}))
	require.False(t, podScanResult.IsError)
	var podRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, podScanResult)), &podRes))
	require.Equal(t, 1, podRes.FindingsCount)
	assert.Equal(t, "Pod", podRes.Findings[0].ResourceKind)
	assert.NotContains(t, podRes.Findings[0].Description, "later Secret sources")

	// 2. Namespace scan: Confirmed Pod finding must NOT disappear due to deduplication against the uncertain StatefulSet
	nsScanResult := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "sts-dedup",
	}))
	require.False(t, nsScanResult.IsError)
	var nsRes SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, nsScanResult)), &nsRes))

	// Should preserve: ConfigMap finding (1), StatefulSet uncertain finding (1), and Pod confirmed finding (1)
	foundSS := false
	foundPod := false
	for _, f := range nsRes.Findings {
		if f.ResourceKind == "StatefulSet" && f.ResourceName == "my-statefulset" {
			foundSS = true
			assert.Contains(t, f.Description, "later Secret sources [db-secret] may override some imported keys")
		}
		if f.ResourceKind == "Pod" && f.ResourceName == "my-statefulset-0" {
			foundPod = true
			assert.NotContains(t, f.Description, "later Secret sources")
		}
	}
	assert.True(t, foundSS, "expected uncertain StatefulSet finding")
	assert.True(t, foundPod, "expected confirmed Pod finding to be preserved in namespace scan")
}

func TestDetectSecretExposure_DynamicVariableRefURI(t *testing.T) {
	// Workload using recommended Kubernetes $(VAR) / ${VAR} / {{ .Template }} interpolation
	// in connection URIs must NOT be flagged as URI_CREDENTIALS or ENV_CREDENTIAL_KEYWORD.
	podSafe := testSecretPod("uri-test", "safe-uri-pod", []map[string]any{
		{
			"name": "app",
			"env": []any{
				map[string]any{
					"name":  "DATABASE_URL",
					"value": "post" + "gres://" + "admin:$(DB_PASSWORD)@db-service:5432/mydb",
				},
				map[string]any{
					"name":  "ANALYTICS_URL",
					"value": "post" + "gres://" + "$(DB_USER):$(DB_PASSWORD)@analytics-db:5432/analytics",
				},
				map[string]any{
					"name":  "CACHE_URL",
					"value": "post" + "gres://" + "admin:${CACHE_PASSWORD}@cache-db:5432/cache",
				},
				map[string]any{
					"name":  "TEMPLATE_URL",
					"value": "post" + "gres://" + "admin:{{ .Values.dbPassword }}@tpl-db:5432/tpl",
				},
			},
		},
	})

	ksServerSafe := newSecretExposureTestServer(t, podSafe)
	resSafe := registeredToolResult(t, dispatchRegisteredTool(t, ksServerSafe, "detect_secret_exposure", map[string]any{
		"namespace": "uri-test",
	}))
	require.False(t, resSafe.IsError)
	var resDataSafe SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resSafe)), &resDataSafe))
	assert.Equal(t, 0, resDataSafe.FindingsCount, "dynamic variable references in URI credentials must be suppressed")

	// Workload with literal credentials in password part must still be flagged as URI_CREDENTIALS
	podExposed := testSecretPod("uri-test", "exposed-uri-pod", []map[string]any{
		{
			"name": "app",
			"env": []any{
				map[string]any{
					"name":  "DATABASE_URL",
					"value": "post" + "gres://" + "admin:" + testPassword() + "@db-service:5432/mydb",
				},
				map[string]any{
					"name":  "COMPOSED_URL",
					"value": "post" + "gres://" + "$(DB_USER):" + testPassword() + "@db-service:5432/mydb",
				},
			},
		},
	})

	ksServerExposed := newSecretExposureTestServer(t, podExposed)
	resExposed := registeredToolResult(t, dispatchRegisteredTool(t, ksServerExposed, "detect_secret_exposure", map[string]any{
		"namespace": "uri-test",
	}))
	require.False(t, resExposed.IsError)
	var resDataExposed SecretExposureResult
	require.NoError(t, json.Unmarshal([]byte(toolResultText(t, resExposed)), &resDataExposed))
	assert.Equal(t, 2, resDataExposed.FindingsCount, "literal credentials in URI must still be flagged")
	for _, f := range resDataExposed.Findings {
		assert.Equal(t, "URI_CREDENTIALS", f.RuleID)
		assert.Equal(t, "High", f.Severity)
	}
}
