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

	assert.Equal(t, 5, res.FindingsCount)
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
				map[string]any{"name": "TOKEN_PATH", "value": "/var/run/token"},
				map[string]any{"name": "SECRET_REF", "value": "app-ref"},
				map[string]any{"name": "TOKEN_TYPE", "value": "Bearer"},
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

	assert.Equal(t, 5, res.FindingsCount)
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

	// 2. Unscoped or ConfigMap scoped -> should return RBAC_DENIED tool error
	resUnscoped := registeredToolResult(t, dispatchRegisteredTool(t, ksServer, "detect_secret_exposure", map[string]any{
		"namespace": "prod",
	}))
	require.True(t, resUnscoped.IsError)
	assert.Contains(t, toolResultText(t, resUnscoped), "RBAC_DENIED")
}
