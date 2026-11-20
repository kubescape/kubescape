package cautils

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
)

// parseTypedHCL parses HCL source and returns the *hclsyntax.Body the typed
// Terraform conversion helpers work on. Test fixtures must parse cleanly;
// expression evaluation errors are what the conversion tests exercise, not
// syntax errors.
func parseTypedHCL(t *testing.T, src string) *hclsyntax.Body {
	t.Helper()
	file, diags := hclsyntax.ParseConfig([]byte(src), "test.tf", hcl.Pos{Line: 1, Column: 1})
	require.False(t, diags.HasErrors(), "fixture must parse: %s", diags)
	body, ok := file.Body.(*hclsyntax.Body)
	require.True(t, ok, "fixture must be hclsyntax")
	return body
}

func TestSnakeToCamel(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"multi-word attribute", "image_pull_secrets", "imagePullSecrets"},
		{"no underscore passes through", "apiVersion", "apiVersion"},
		{"single word", "spec", "spec"},
		{"empty segment from double underscore is skipped", "host__alias", "hostAlias"},
		{"trailing underscore segment is dropped", "trailing_", "trailing"},
		{"leading and trailing underscores are dropped", "_init_container_", "InitContainer"},
		{"host pid initialism", "host_pid", "hostPID"},
		{"host ipc initialism", "host_ipc", "hostIPC"},
		{"host ip initialism", "host_ip", "hostIP"},
		{"plural ips initialism", "external_ips", "externalIPs"},
		{"multi-word ip initialism", "load_balancer_ip", "loadBalancerIP"},
		{"urls initialism", "non_resource_urls", "nonResourceURLs"},
		{"id initialism", "volume_id", "volumeID"},
		{"api initialism", "downward_api", "downwardAPI"},
		{"api as first word stays lowercase", "api_groups", "apiGroups"},
		{"initialism as first word stays lowercase", "ip_families", "ipFamilies"},
		{"word containing an initialism is not changed", "pid_limit", "pidLimit"},
		{"target cpu utilization percentage initialism", "target_cpu_utilization_percentage", "targetCPUUtilizationPercentage"},
		{"cpu as first word stays lowercase", "cpu_limit", "cpuLimit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, snakeToCamel(tc.in))
		})
	}
}

func TestFieldNameFor(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plural override wins for container", "container", "containers"},
		{"plural override for init_container", "init_container", "initContainers"},
		{"plural override for path", "path", "paths"},
		{"plural override for sysctl", "sysctl", "sysctls"},
		{"plural override for http_header", "http_header", "httpHeaders"},
		{"plural override for limit", "limit", "limits"},
		{"plural override for metric", "metric", "metrics"},
		{"plural override for policy", "policy", "policies"},
		{"plural override for match_expression", "match_expression", "matchExpressions"},
		{"plural override for node_selector_term", "node_selector_term", "nodeSelectorTerms"},
		{"non-overridden label falls back to camelCase", "metadata", "metadata"},
		{"multi-word fallback", "image_pull_policy", "imagePullPolicy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fieldNameFor(tc.in))
		})
	}
}

func TestAttributeNameFor(t *testing.T) {
	assert.Equal(t, "port", attributeNameFor("port"))
	assert.Equal(t, "containerPort", attributeNameFor("container_port"))
	assert.Equal(t, "protocol", attributeNameFor("protocol"))
	assert.Equal(t, "diskURI", attributeNameFor("data_disk_uri"))
}

func TestAttributeValueFor(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		attrName string
		in       interface{}
		want     interface{}
	}{
		{
			name:     "quoted numeric port in network policy ingress ports converts to json.Number",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "8125",
			want:     json.Number("8125"),
		},
		{
			name:     "quoted numeric port with leading zeros in network policy ingress canonicalizes without leading zeros",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "080",
			want:     json.Number("80"),
		},
		{
			name:     "all-zero numeric port in network policy ingress canonicalizes to zero",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "00",
			want:     json.Number("0"),
		},
		{
			name:     "single zero numeric port in network policy ingress preserved as zero",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "0",
			want:     json.Number("0"),
		},
		{
			name:     "quoted numeric port in network policy egress ports converts to json.Number",
			path:     "kubernetes_network_policy_v1.np.spec.egress.ports",
			attrName: "port",
			in:       "53",
			want:     json.Number("53"),
		},
		{
			name:     "quoted numeric end_port in network policy converts to json.Number",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "end_port",
			in:       "8200",
			want:     json.Number("8200"),
		},
		{
			name:     "unquoted numeric port already json.Number passes through",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       json.Number("8080"),
			want:     json.Number("8080"),
		},
		{
			name:     "named port in network policy preserved as string",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "http",
			want:     "http",
		},
		{
			name:     "kebab-case named port preserved as string",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "dns-tcp",
			want:     "dns-tcp",
		},
		{
			name:     "quoted numeric service_port in legacy ingress backend converts to json.Number",
			path:     "kubernetes_ingress.web.spec.rules.http.paths.backend",
			attrName: "service_port",
			in:       "8080",
			want:     json.Number("8080"),
		},
		{
			name:     "quoted numeric service_port with leading zero in legacy ingress backend canonicalizes to json.Number",
			path:     "kubernetes_ingress.web.spec.rules.http.paths.backend",
			attrName: "service_port",
			in:       "08080",
			want:     json.Number("8080"),
		},
		{
			name:     "quoted numeric number in ingress v1 backend service port converts to json.Number",
			path:     "kubernetes_ingress_v1.web.spec.rules.http.paths.backend.service.port",
			attrName: "number",
			in:       "8080",
			want:     json.Number("8080"),
		},
		{
			name:     "quoted numeric number with leading zero in ingress v1 backend service port canonicalizes",
			path:     "kubernetes_ingress_v1.web.spec.rules.http.paths.backend.service.port",
			attrName: "number",
			in:       "080",
			want:     json.Number("80"),
		},
		{
			name:     "named port in ingress v1 backend service port preserved as string",
			path:     "kubernetes_ingress_v1.web.spec.rules.http.paths.backend.service.port",
			attrName: "name",
			in:       "http",
			want:     "http",
		},
		{
			name:     "named service_port in legacy ingress backend preserved as string",
			path:     "kubernetes_ingress.web.spec.rules.http.paths.backend",
			attrName: "service_port",
			in:       "http",
			want:     "http",
		},
		{
			name:     "service_port in non-legacy ingress v1 untouched",
			path:     "kubernetes_ingress_v1.web.spec.backend",
			attrName: "service_port",
			in:       "8080",
			want:     "8080",
		},
		{
			name:     "non-port attribute in ports block untouched",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "protocol",
			in:       "UDP",
			want:     "UDP",
		},
		{
			name:     "quoted numeric port in non-networkpolicy block untouched",
			path:     "kubernetes_deployment.app.spec.template.spec.containers.ports",
			attrName: "port",
			in:       "80",
			want:     "80",
		},
		{
			name:     "empty string untouched",
			path:     "kubernetes_network_policy.np.spec.ingress.ports",
			attrName: "port",
			in:       "",
			want:     "",
		},
		{
			name:     "quoted numeric min_available in PDB converts to json.Number",
			path:     "kubernetes_pod_disruption_budget.pdb.spec",
			attrName: "min_available",
			in:       "1",
			want:     json.Number("1"),
		},
		{
			name:     "percentage string min_available in PDB preserved as string",
			path:     "kubernetes_pod_disruption_budget_v1.pdb.spec",
			attrName: "min_available",
			in:       "50%",
			want:     "50%",
		},
		{
			name:     "quoted numeric max_unavailable in PDB converts to json.Number",
			path:     "kubernetes_pod_disruption_budget.pdb.spec",
			attrName: "max_unavailable",
			in:       "0",
			want:     json.Number("0"),
		},
		{
			name:     "percentage string max_unavailable in PDB preserved as string",
			path:     "kubernetes_pod_disruption_budget_v1.pdb.spec",
			attrName: "max_unavailable",
			in:       "25%",
			want:     "25%",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, attributeValueFor(tc.path, tc.attrName, tc.in))
		})
	}
}

func TestHclResourceBodyToMapStripsMetaArguments(t *testing.T) {
	// depends_on and provider reference other resources/providers that the
	// var-only evalCtx can never resolve; they must be stripped before
	// expression evaluation rather than failing into errs. Top-level
	// lifecycle, provisioner and connection are Terraform meta blocks and
	// must be stripped the same way.
	src := `
resource "kubernetes_deployment" "app" {
  depends_on  = [kubernetes_pod.elsewhere]
  provider    = kubernetes.alt
  count       = 1
  for_each    = {}
  lifecycle {
    ignore_changes = ["metadata"]
  }
  provisioner "local-exec" {
    command = "echo"
  }
  connection {
    type = "ssh"
  }
  metadata {
    name = "app"
  }
  spec {
    replicas = 2
  }
}
`
	body := parseTypedHCL(t, src)
	require.Len(t, body.Blocks, 1)

	var errs []error
	out := hclResourceBodyToMap(body.Blocks[0].Body, &hcl.EvalContext{}, &errs, "kubernetes_deployment.app")

	require.Empty(t, errs, "meta-arguments must be stripped before evaluation, not left to fail")

	want := map[string]interface{}{
		"metadata": map[string]interface{}{"name": "app", "namespace": "default"},
		"spec":     map[string]interface{}{"replicas": json.Number("2")},
	}
	assert.Equal(t, want, out)

	for _, stripped := range []string{"depends_on", "provider", "count", "for_each", "lifecycle", "provisioner", "connection"} {
		assert.NotContains(t, out, stripped)
	}
}

func TestHclBodyToMapKeepsNestedLifecycle(t *testing.T) {
	// resourceMetaBlocks apply ONLY at the resource's top level. A container's
	// own lifecycle block (postStart/preStop hooks) is a legitimate Kubernetes
	// field and must still be converted, with snake_case nested keys camelCased.
	src := `
container {
  name = "app"
  lifecycle {
    post_start {
      exec = ["sleep", "30"]
    }
  }
}
`
	body := parseTypedHCL(t, src)
	require.Len(t, body.Blocks, 1)

	var errs []error
	out := hclBodyToMap(body.Blocks[0].Body, &hcl.EvalContext{}, &errs, "container")

	require.Empty(t, errs)
	want := map[string]interface{}{
		"name": "app",
		"lifecycle": map[string]interface{}{
			"postStart": map[string]interface{}{
				"exec": []interface{}{"sleep", "30"},
			},
		},
	}
	assert.Equal(t, want, out)
}

func TestHclBodyToMapRepeatableBlocks(t *testing.T) {
	t.Run("repeated blocks encode as an array in source order", func(t *testing.T) {
		src := `
metadata {
  name = "one"
}
container {
  name = "c1"
}
container {
  name = "c2"
}
`
		var errs []error
		out := hclBodyToMap(parseTypedHCL(t, src), &hcl.EvalContext{}, &errs, "pod")

		require.Empty(t, errs)
		want := map[string]interface{}{
			"metadata": map[string]interface{}{"name": "one"},
			"containers": []interface{}{
				map[string]interface{}{"name": "c1"},
				map[string]interface{}{"name": "c2"},
			},
		}
		assert.Equal(t, want, out)
	})

	t.Run("single repeatable block still encodes as an array", func(t *testing.T) {
		src := `
container {
  name = "solo"
}
`
		var errs []error
		out := hclBodyToMap(parseTypedHCL(t, src), &hcl.EvalContext{}, &errs, "pod")

		require.Empty(t, errs)
		want := map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{"name": "solo"}},
		}
		assert.Equal(t, want, out)
	})
}

func TestExtractTypedResources(t *testing.T) {
	src := `
resource "kubernetes_deployment_v1" "web" {
  replicas = 3
}

resource "kubernetes_pod" "explicit-name" {
  metadata {
    name = "custom-name"
  }
}

resource "kubernetes_role_binding" "rb" {
}

resource "kubernetes_deployment" "legacy-web" {
  replicas = 2
}

resource "kubernetes_foo_bar" "unsupported" {
  name = "skip-me"
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 4, "unsupported resource types must be skipped")

	assert.Equal(t, "apps/v1", manifests[0]["apiVersion"])
	assert.Equal(t, "Deployment", manifests[0]["kind"])
	assert.Equal(t, json.Number("3"), manifests[0]["replicas"])
	assert.Equal(t, map[string]interface{}{"name": "web"}, manifests[0]["metadata"], "metadata.name must be defaulted from the Terraform label")

	assert.Equal(t, "v1", manifests[1]["apiVersion"])
	assert.Equal(t, "Pod", manifests[1]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "custom-name", "namespace": "default"}, manifests[1]["metadata"], "explicit metadata.name must be preserved")

	assert.Equal(t, "rbac.authorization.k8s.io/v1", manifests[2]["apiVersion"])
	assert.Equal(t, "RoleBinding", manifests[2]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "rb"}, manifests[2]["metadata"])

	assert.Equal(t, "apps/v1", manifests[3]["apiVersion"])
	assert.Equal(t, "Deployment", manifests[3]["kind"])
	assert.Equal(t, json.Number("2"), manifests[3]["replicas"])
	assert.Equal(t, map[string]interface{}{"name": "legacy-web"}, manifests[3]["metadata"])
}

func TestExtractTypedResourcesInitialismFields(t *testing.T) {
	src := `
resource "kubernetes_pod_v1" "host" {
  spec {
    host_pid = true
    host_ipc = true
    container {
      name = "app"
      port {
        container_port = 80
        host_ip        = "0.0.0.0"
      }
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 1)
	spec, ok := manifests[0]["spec"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, spec["hostPID"])
	assert.Equal(t, true, spec["hostIPC"])
	ports := spec["containers"].([]interface{})[0].(map[string]interface{})["ports"].([]interface{})
	assert.Equal(t, "0.0.0.0", ports[0].(map[string]interface{})["hostIP"])
}

// A downward API volume is downwardAPI in the pod spec. Controls key on it: the
// mount security rule exempts a mount of one as read-only by volume.downwardAPI,
// so under another name the mount was reported as writable.
func TestExtractTypedResourcesDownwardAPIVolume(t *testing.T) {
	src := `
resource "kubernetes_pod_v1" "info" {
  spec {
    container {
      name  = "app"
      image = "nginx"
      volume_mount {
        name       = "podinfo"
        mount_path = "/etc/podinfo"
      }
    }
    volume {
      name = "podinfo"
      downward_api {
        items {
          path = "labels"
          field_ref {
            field_path = "metadata.labels"
          }
        }
      }
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 1)
	spec, ok := manifests[0]["spec"].(map[string]interface{})
	require.True(t, ok)
	volumes, ok := spec["volumes"].([]interface{})
	require.True(t, ok)
	require.Len(t, volumes, 1)
	volume := volumes[0].(map[string]interface{})
	assert.Contains(t, volume, "downwardAPI")
	assert.NotContains(t, volume, "downwardApi")
}

func TestExtractTypedResourcesVersionedRBAC(t *testing.T) {
	src := `
resource "kubernetes_role_v1" "reader" {
  metadata {
    namespace = "apps"
  }
  rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_role_binding_v1" "reader" {
  metadata {
    namespace = "apps"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "reader"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "ci"
    namespace = "apps"
  }
}

resource "kubernetes_cluster_role_v1" "admin" {
}

resource "kubernetes_cluster_role_binding_v1" "admin" {
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 4)

	assert.Equal(t, map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]interface{}{"name": "reader", "namespace": "apps"},
		"rules": []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{"secrets"},
				"verbs":     []interface{}{"get", "list"},
			},
		},
	}, manifests[0])

	assert.Equal(t, map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]interface{}{"name": "reader", "namespace": "apps"},
		"roleRef":    map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
		"subjects": []interface{}{
			map[string]interface{}{"kind": "ServiceAccount", "name": "ci", "namespace": "apps"},
		},
	}, manifests[1])

	assert.Equal(t, "ClusterRole", manifests[2]["kind"])
	assert.Equal(t, "ClusterRoleBinding", manifests[3]["kind"])
}

func TestExtractTypedResourcesServiceAccountAndHostAliases(t *testing.T) {
	src := `
resource "kubernetes_default_service_account" "my_custom_label" {
  metadata {
    namespace = "kube-system"
  }
  automount_service_account_token = false
  secret {
    name = "default-token"
  }
  image_pull_secret {
    name = "regcred"
  }
}

resource "kubernetes_default_service_account_v1" "default_v1" {
  metadata {
    name = "custom-default"
  }
  secret {
    name = "s1"
  }
  secret {
    name = "s2"
  }
}

resource "kubernetes_service_account_v1" "app" {
  metadata {
    name = "app"
  }
  secret {
    name = "app-token"
  }
  image_pull_secret {
    name = "app-cred"
  }
}

resource "kubernetes_pod_v1" "pod_with_host_aliases" {
  spec {
    host_aliases {
      ip        = "127.0.0.1"
      hostnames = ["local.dev"]
    }
    container {
      name  = "app"
      image = "nginx"
    }
    volume {
      name = "sec-vol"
      secret {
        secret_name = "pod-secret"
      }
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 4)

	// 1. kubernetes_default_service_account maps to v1/ServiceAccount with secrets and imagePullSecrets arrays
	assert.Equal(t, "v1", manifests[0]["apiVersion"])
	assert.Equal(t, "ServiceAccount", manifests[0]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "default", "namespace": "kube-system"}, manifests[0]["metadata"],
		"default service account must default metadata.name to 'default' even when Terraform label differs")
	assert.Equal(t, false, manifests[0]["automountServiceAccountToken"])
	assert.Equal(t, []interface{}{
		map[string]interface{}{"name": "default-token"},
	}, manifests[0]["secrets"], "single secret block must encode as secrets array")
	assert.Equal(t, []interface{}{
		map[string]interface{}{"name": "regcred"},
	}, manifests[0]["imagePullSecrets"], "single image_pull_secret block must encode as imagePullSecrets array")

	// 2. kubernetes_default_service_account_v1 maps to v1/ServiceAccount with multiple secrets
	assert.Equal(t, "v1", manifests[1]["apiVersion"])
	assert.Equal(t, "ServiceAccount", manifests[1]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "custom-default", "namespace": "default"}, manifests[1]["metadata"])
	assert.Equal(t, []interface{}{
		map[string]interface{}{"name": "s1"},
		map[string]interface{}{"name": "s2"},
	}, manifests[1]["secrets"], "multiple secret blocks must preserve all entries in secrets array")

	// 3. kubernetes_service_account_v1 maps single secret and image_pull_secret to arrays
	assert.Equal(t, "v1", manifests[2]["apiVersion"])
	assert.Equal(t, "ServiceAccount", manifests[2]["kind"])
	assert.Equal(t, []interface{}{
		map[string]interface{}{"name": "app-token"},
	}, manifests[2]["secrets"])
	assert.Equal(t, []interface{}{
		map[string]interface{}{"name": "app-cred"},
	}, manifests[2]["imagePullSecrets"])

	// 4. Pod with host_aliases and volume.secret: host_aliases becomes array, volume.secret remains an object
	podSpec := manifests[3]["spec"].(map[string]interface{})
	assert.Equal(t, []interface{}{
		map[string]interface{}{
			"ip":        "127.0.0.1",
			"hostnames": []interface{}{"local.dev"},
		},
	}, podSpec["hostAliases"], "single host_aliases block must encode as array")

	volumes := podSpec["volumes"].([]interface{})
	require.Len(t, volumes, 1)
	vol := volumes[0].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"secretName": "pod-secret"}, vol["secret"],
		"volume.secret must remain a nested object and not be converted to secrets array")
}

func TestExtractTypedResourcesSkipsInvalidBlocks(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"non-resource block with two labels", `not_a_resource "kubernetes_deployment" "ignored" {}`},
		{"resource block with no labels", `resource {}`},
		{"resource block with one label", `resource "kubernetes_deployment" {}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifests, errs := extractTypedResources(parseTypedHCL(t, tc.src), &hcl.EvalContext{})

			assert.Empty(t, errs)
			assert.Empty(t, manifests)
		})
	}
}

func TestExtractTypedResourcesCollectsUnresolvableAttributes(t *testing.T) {
	// Attributes that cannot be evaluated against the var-only evalCtx are
	// recorded in errs and left unset rather than guessed at, matching the
	// kubernetes_manifest policy.
	src := `
resource "kubernetes_config_map" "bad" {
  data = var.missing
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Len(t, errs, 1)
	require.Len(t, manifests, 1)

	obj := manifests[0]
	assert.Equal(t, "v1", obj["apiVersion"])
	assert.Equal(t, "ConfigMap", obj["kind"])
	assert.Equal(t, map[string]interface{}{"name": "bad"}, obj["metadata"])
	assert.NotContains(t, obj, "data", "unresolvable attributes must be left unset")
}

func TestExtractTypedResourcesNonHclBody(t *testing.T) {
	// A body that is not hclsyntax (e.g. an empty body) yields nothing rather
	// than guessing.
	manifests, errs := extractTypedResources(hcl.EmptyBody(), &hcl.EvalContext{})

	assert.Nil(t, manifests)
	assert.Nil(t, errs)
}

func TestExtractTypedResourcesNetworkPolicyAndUnversionedAliases(t *testing.T) {
	src := `
resource "kubernetes_daemon_set" "ds" {
  metadata {
    name      = "fluentd"
    namespace = "kube-system"
  }
}

resource "kubernetes_cron_job" "cj" {
  metadata {
    name = "backup"
  }
}

resource "kubernetes_ingress" "ing" {
  metadata {
    name = "web-ingress"
  }
  spec {
    rule {
      host = "example.com"
      http {
        path {
          path = "/api"
          backend {
            service_name = "api-svc"
            service_port = "8080"
          }
        }
        path {
          path = "/named"
          backend {
            service_name = "named-svc"
            service_port = "http"
          }
        }
      }
    }
    tls {
      hosts = ["example.com"]
      secret_name = "example-tls"
    }
  }
}

resource "kubernetes_network_policy" "np" {
  metadata {
    name      = "default-deny-ingress"
    namespace = "prod"
  }
  spec {
    pod_selector {
      match_labels = {
        app = "backend"
      }
    }
    policy_types = ["Ingress", "Egress"]
    ingress {
      from {
        namespace_selector {
          match_labels = {
            env = "prod"
          }
        }
      }
      ports {
        port     = 8080
        protocol = "TCP"
      }
      ports {
        port     = "8125"
        protocol = "UDP"
      }
      ports {
        port     = "080"
        protocol = "TCP"
      }
      ports {
        port     = "http"
        protocol = "TCP"
      }
    }
    egress {
      to {
        ip_block {
          cidr = "10.0.0.0/8"
        }
      }
    }
  }
}

resource "kubernetes_network_policy_v1" "np_v1" {
  metadata {
    name = "allow-dns"
  }
  spec {
    policy_types = ["Egress"]
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})

	require.Empty(t, errs)
	require.Len(t, manifests, 5)

	assert.Equal(t, "apps/v1", manifests[0]["apiVersion"])
	assert.Equal(t, "DaemonSet", manifests[0]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "fluentd", "namespace": "kube-system"}, manifests[0]["metadata"])

	assert.Equal(t, "batch/v1", manifests[1]["apiVersion"])
	assert.Equal(t, "CronJob", manifests[1]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "backup", "namespace": "default"}, manifests[1]["metadata"])

	assert.Equal(t, "networking.k8s.io/v1beta1", manifests[2]["apiVersion"])
	assert.Equal(t, "Ingress", manifests[2]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "web-ingress", "namespace": "default"}, manifests[2]["metadata"])

	ingSpec, ok := manifests[2]["spec"].(map[string]interface{})
	require.True(t, ok)
	rulesSlice, ok := ingSpec["rules"].([]interface{})
	require.True(t, ok, "spec.rules must be a slice")
	require.Len(t, rulesSlice, 1)

	httpRule, ok := rulesSlice[0].(map[string]interface{})["http"].(map[string]interface{})
	require.True(t, ok)
	pathsSlice, ok := httpRule["paths"].([]interface{})
	require.True(t, ok, "http.paths must be a slice")
	require.Len(t, pathsSlice, 2)

	path0, ok := pathsSlice[0].(map[string]interface{})
	require.True(t, ok)
	backend0, ok := path0["backend"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, json.Number("8080"), backend0["servicePort"], "quoted numeric service_port in legacy ingress backend must be normalized to json.Number")

	path1, ok := pathsSlice[1].(map[string]interface{})
	require.True(t, ok)
	backend1, ok := path1["backend"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "http", backend1["servicePort"], "named service_port in legacy ingress backend must be preserved as string")

	tlsSlice, ok := ingSpec["tls"].([]interface{})
	require.True(t, ok, "spec.tls must be a slice")
	require.Len(t, tlsSlice, 1)

	assert.Equal(t, "networking.k8s.io/v1", manifests[3]["apiVersion"])
	assert.Equal(t, "NetworkPolicy", manifests[3]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "default-deny-ingress", "namespace": "prod"}, manifests[3]["metadata"])

	spec, ok := manifests[3]["spec"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"Ingress", "Egress"}, spec["policyTypes"])

	ingressSlice, ok := spec["ingress"].([]interface{})
	require.True(t, ok, "spec.ingress must be a slice")
	require.Len(t, ingressSlice, 1)

	ingressRule, ok := ingressSlice[0].(map[string]interface{})
	require.True(t, ok)
	fromSlice, ok := ingressRule["from"].([]interface{})
	require.True(t, ok, "ingress.from must be a slice")
	require.Len(t, fromSlice, 1)

	portsSlice, ok := ingressRule["ports"].([]interface{})
	require.True(t, ok, "ingress.ports must be a slice")
	require.Len(t, portsSlice, 4)

	portEntry0, ok := portsSlice[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, json.Number("8080"), portEntry0["port"])
	assert.Equal(t, "TCP", portEntry0["protocol"])
	assert.NotContains(t, portEntry0, "ports", "scalar port attribute must not be pluralized to ports")

	portEntry1, ok := portsSlice[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, json.Number("8125"), portEntry1["port"], "quoted numeric port must be normalized to json.Number")
	assert.Equal(t, "UDP", portEntry1["protocol"])

	portEntry2, ok := portsSlice[2].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, json.Number("80"), portEntry2["port"], "quoted numeric port with leading zeros must be canonicalized to json.Number")
	assert.Equal(t, "TCP", portEntry2["protocol"])

	portEntry3, ok := portsSlice[3].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "http", portEntry3["port"], "named port must be preserved as string")
	assert.Equal(t, "TCP", portEntry3["protocol"])

	egressSlice, ok := spec["egress"].([]interface{})
	require.True(t, ok, "spec.egress must be a slice")
	require.Len(t, egressSlice, 1)

	egressRule, ok := egressSlice[0].(map[string]interface{})
	require.True(t, ok)
	toSlice, ok := egressRule["to"].([]interface{})
	require.True(t, ok, "egress.to must be a slice")
	require.Len(t, toSlice, 1)

	assert.Equal(t, "networking.k8s.io/v1", manifests[4]["apiVersion"])
	assert.Equal(t, "NetworkPolicy", manifests[4]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "allow-dns", "namespace": "default"}, manifests[4]["metadata"])

	for i, m := range manifests {
		data, err := json.Marshal(m)
		require.NoError(t, err, "manifest %d must marshal cleanly to valid JSON without error", i)
		assert.NotEmpty(t, data)
	}
}

func TestExtractTypedResourcesIngressBackendServicePortAndPathType(t *testing.T) {
	src := `
resource "kubernetes_ingress_v1" "ing" {
  metadata {
    name = "my-ingress"
  }
  spec {
    tls {
      hosts       = ["example.com"]
      secret_name = "example-tls"
    }
    default_backend {
      service {
        name = "default-svc"
        port {
          number = 443
        }
      }
    }
    rule {
      host = "example.com"
      http {
        path {
          path      = "/api"
          path_type = "Prefix"
          backend {
            service {
              name = "api-svc"
              port {
                number = 8080
              }
            }
          }
        }
        path {
          path = "/quoted"
          backend {
            service {
              name = "quoted-svc"
              port {
                number = "8443"
              }
            }
          }
        }
        path {
          path = "/named"
          backend {
            service {
              name = "named-svc"
              port {
                name = "http"
              }
            }
          }
        }
        path {
          path      = "/null-type"
          path_type = null
          backend {
            service {
              name = "null-type-svc"
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Empty(t, errs)
	require.Len(t, manifests, 1)

	obj := manifests[0]
	assert.Equal(t, "networking.k8s.io/v1", obj["apiVersion"])
	assert.Equal(t, "Ingress", obj["kind"])

	spec, ok := obj["spec"].(map[string]interface{})
	require.True(t, ok)

	// Single tls block must be converted to an array.
	tlsSlice, ok := spec["tls"].([]interface{})
	require.True(t, ok, "spec.tls must be a slice")
	require.Len(t, tlsSlice, 1)

	// default_backend service port must be an object, not a slice or named ports.
	defBackend, ok := spec["defaultBackend"].(map[string]interface{})
	require.True(t, ok)
	defSvc, ok := defBackend["service"].(map[string]interface{})
	require.True(t, ok)
	assert.NotContains(t, defSvc, "ports", "service port must not be pluralized to ports")
	defPort, ok := defSvc["port"].(map[string]interface{})
	require.True(t, ok, "default backend service port must be an object")
	assert.Equal(t, json.Number("443"), defPort["number"])

	// rules and paths
	rules, ok := spec["rules"].([]interface{})
	require.True(t, ok)
	require.Len(t, rules, 1)

	httpRule, ok := rules[0].(map[string]interface{})["http"].(map[string]interface{})
	require.True(t, ok)
	paths, ok := httpRule["paths"].([]interface{})
	require.True(t, ok, "http.paths must be a slice")
	require.Len(t, paths, 4)

	// Path 0: explicit path_type = "Prefix", numeric literal port
	p0, ok := paths[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Prefix", p0["pathType"], "explicit pathType must be preserved")
	b0, ok := p0["backend"].(map[string]interface{})
	require.True(t, ok)
	svc0, ok := b0["service"].(map[string]interface{})
	require.True(t, ok)
	assert.NotContains(t, svc0, "ports", "service port must not be pluralized to ports")
	port0, ok := svc0["port"].(map[string]interface{})
	require.True(t, ok, "service port must be an object")
	assert.Equal(t, json.Number("8080"), port0["number"])

	// Path 1: omitted path_type defaults to ImplementationSpecific, quoted numeric port
	p1, ok := paths[1].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ImplementationSpecific", p1["pathType"], "omitted pathType must default to ImplementationSpecific")
	b1, ok := p1["backend"].(map[string]interface{})
	require.True(t, ok)
	svc1, ok := b1["service"].(map[string]interface{})
	require.True(t, ok)
	assert.NotContains(t, svc1, "ports")
	port1, ok := svc1["port"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, json.Number("8443"), port1["number"], "quoted numeric port must be normalized to json.Number")

	// Path 2: omitted path_type defaults to ImplementationSpecific, named port
	p2, ok := paths[2].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ImplementationSpecific", p2["pathType"])
	b2, ok := p2["backend"].(map[string]interface{})
	require.True(t, ok)
	svc2, ok := b2["service"].(map[string]interface{})
	require.True(t, ok)
	port2, ok := svc2["port"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "http", port2["name"], "named port must be preserved as string")

	// Path 3: explicit path_type = null defaults to ImplementationSpecific
	p3, ok := paths[3].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ImplementationSpecific", p3["pathType"], "null pathType must default to ImplementationSpecific")
	b3, ok := p3["backend"].(map[string]interface{})
	require.True(t, ok)
	svc3, ok := b3["service"].(map[string]interface{})
	require.True(t, ok)
	port3, ok := svc3["port"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, json.Number("80"), port3["number"])

	// Verify serialization and ReadFile
	data, err := json.Marshal(obj)
	require.NoError(t, err)

	workloads, err := ReadFile(data, JSON_FILE_FORMAT)
	require.NoError(t, err, "Ingress manifest must deserialize via ReadFile cleanly")
	require.Len(t, workloads, 1)
	assert.Equal(t, "Ingress", workloads[0].GetKind())

	// Verify unmarshaling into typed networkingv1.Ingress
	var typedIng networkingv1.Ingress
	err = json.Unmarshal(data, &typedIng)
	require.NoError(t, err, "Ingress manifest must unmarshal cleanly into networkingv1.Ingress")
	assert.Equal(t, int32(443), typedIng.Spec.DefaultBackend.Service.Port.Number)
	require.Len(t, typedIng.Spec.Rules[0].HTTP.Paths, 4)
	assert.Equal(t, int32(8080), typedIng.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number)
	assert.Equal(t, int32(8443), typedIng.Spec.Rules[0].HTTP.Paths[1].Backend.Service.Port.Number)
	assert.Equal(t, "http", typedIng.Spec.Rules[0].HTTP.Paths[2].Backend.Service.Port.Name)
	assert.Equal(t, int32(80), typedIng.Spec.Rules[0].HTTP.Paths[3].Backend.Service.Port.Number)
	require.NotNil(t, typedIng.Spec.Rules[0].HTTP.Paths[3].PathType)
	assert.Equal(t, networkingv1.PathTypeImplementationSpecific, *typedIng.Spec.Rules[0].HTTP.Paths[3].PathType)
}

func TestExtractTypedResourcesIngressPathTypeNull(t *testing.T) {
	src := `
resource "kubernetes_ingress_v1" "ing_null_path_type" {
  metadata {
    name = "null-path-type"
  }
  spec {
    rule {
      http {
        path {
          path      = "/test"
          path_type = null
          backend {
            service {
              name = "test-svc"
              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}
`
	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Empty(t, errs)
	require.Len(t, manifests, 1)

	spec, ok := manifests[0]["spec"].(map[string]interface{})
	require.True(t, ok)
	rules, ok := spec["rules"].([]interface{})
	require.True(t, ok)
	httpRule, ok := rules[0].(map[string]interface{})["http"].(map[string]interface{})
	require.True(t, ok)
	paths, ok := httpRule["paths"].([]interface{})
	require.True(t, ok)
	require.Len(t, paths, 1)

	p0, ok := paths[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "ImplementationSpecific", p0["pathType"], "null pathType must default to ImplementationSpecific")

	data, err := json.Marshal(manifests[0])
	require.NoError(t, err)

	var typedIng networkingv1.Ingress
	err = json.Unmarshal(data, &typedIng)
	require.NoError(t, err, "Ingress manifest with null pathType must unmarshal cleanly into networkingv1.Ingress")
	require.Len(t, typedIng.Spec.Rules[0].HTTP.Paths, 1)
	require.NotNil(t, typedIng.Spec.Rules[0].HTTP.Paths[0].PathType)
	assert.Equal(t, networkingv1.PathTypeImplementationSpecific, *typedIng.Spec.Rules[0].HTTP.Paths[0].PathType)
}

func TestExtractTypedResourcesStorageAndPolicyResources(t *testing.T) {
	src := `
resource "kubernetes_persistent_volume_claim" "pvc" {
  metadata {
    name = "data-pvc"
  }
  spec {
    access_modes = ["ReadWriteOnce"]
    storage_class_name = "fast"
    resources {
      requests = {
        storage = "10Gi"
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim_v1" "pvc_v1" {
  metadata {
    name      = "log-pvc"
    namespace = "monitoring"
  }
}

resource "kubernetes_persistent_volume" "pv" {
  metadata {
    name = "data-pv"
  }
  spec {
    capacity = {
      storage = "50Gi"
    }
    access_modes                     = ["ReadWriteMany"]
    persistent_volume_reclaim_policy = "Retain"
    persistent_volume_source {
      nfs {
        path   = "/export"
        server = "nfs.internal"
      }
    }
    node_affinity {
      required {
        node_selector_term {
          match_expressions {
            key      = "topology.kubernetes.io/zone"
            operator = "In"
            values   = ["us-east-1a"]
          }
        }
      }
    }
  }
}

resource "kubernetes_persistent_volume_v1" "pv_v1" {
  metadata {
    name = "log-pv"
  }
  spec {
    persistent_volume_source {
      azure_disk {
        caching_mode  = "None"
        data_disk_uri = "https://example.blob.core.windows.net/vhds/disk.vhd"
        disk_name     = "disk.vhd"
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget" "pdb" {
  metadata {
    name = "api-pdb"
  }
  spec {
    min_available = "1"
    selector {
      match_labels = {
        app = "api"
      }
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "pdb_v1" {
  metadata {
    name      = "worker-pdb"
    namespace = "workers"
  }
  spec {
    max_unavailable = "30%"
  }
}

resource "kubernetes_resource_quota" "quota" {
  metadata {
    name = "compute-quota"
  }
  spec {
    hard = {
      pods = "20"
    }
    scope_selector {
      match_expression {
        scope_name = "PriorityClass"
        operator   = "In"
        values     = ["high"]
      }
    }
  }
}

resource "kubernetes_resource_quota_v1" "quota_v1" {
  metadata {
    name      = "mem-quota"
    namespace = "apps"
  }
}

resource "kubernetes_limit_range" "limits" {
  metadata {
    name = "core-limits"
  }
  spec {
    limit {
      type = "Container"
      default_request = {
        cpu = "100m"
      }
    }
  }
}

resource "kubernetes_limit_range_v1" "limits_v1" {
  metadata {
    name      = "pod-limits"
    namespace = "dev"
  }
}

resource "kubernetes_horizontal_pod_autoscaler" "hpa" {
  metadata {
    name = "web-hpa"
  }
  spec {
    max_replicas                      = 10
    target_cpu_utilization_percentage = 80
    scale_target_ref {
      kind = "Deployment"
      name = "web"
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v1" "hpa_v1" {
  metadata {
    name      = "api-hpa"
    namespace = "api"
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "hpa_v2" {
  metadata {
    name = "v2-hpa"
  }
  spec {
    min_replicas = 2
    max_replicas = 5
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = "v2-app"
    }
    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type                = "Utilization"
          average_utilization = 60
        }
      }
    }
    metric {
      type = "External"
      external {
        metric {
          name = "queue_messages"
        }
        target {
          type  = "Value"
          value = "30"
        }
      }
    }
    behavior {
      scale_up {
        policy {
          type           = "Percent"
          value          = 100
          period_seconds = 15
        }
      }
    }
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2beta2" "hpa_v2beta2" {
  metadata {
    name = "v2beta2-hpa"
  }
}

resource "kubernetes_priority_class" "pc" {
  metadata {
    name = "high-priority"
  }
  value          = 1000000
  global_default = true
}

resource "kubernetes_priority_class_v1" "pc_v1" {
  metadata {
    name = "critical-priority"
  }
  value = 2000000
}
`

	manifests, errs := extractTypedResources(parseTypedHCL(t, src), &hcl.EvalContext{})
	require.Empty(t, errs)
	require.Len(t, manifests, 16)

	// PVC: namespaced, receives provider default namespace "default"
	pvc := manifests[0]
	assert.Equal(t, "v1", pvc["apiVersion"])
	assert.Equal(t, "PersistentVolumeClaim", pvc["kind"])
	assert.Equal(t, map[string]interface{}{"name": "data-pvc", "namespace": "default"}, pvc["metadata"])
	pvcSpec := pvc["spec"].(map[string]interface{})
	assert.Equal(t, []interface{}{"ReadWriteOnce"}, pvcSpec["accessModes"])
	assert.Equal(t, "fast", pvcSpec["storageClassName"])

	// PVC v1 with explicit namespace
	pvcV1 := manifests[1]
	assert.Equal(t, "v1", pvcV1["apiVersion"])
	assert.Equal(t, "PersistentVolumeClaim", pvcV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "log-pvc", "namespace": "monitoring"}, pvcV1["metadata"])

	// PV: cluster-scoped, NO namespace in metadata; persistent_volume_source is flattened
	pv := manifests[2]
	assert.Equal(t, "v1", pv["apiVersion"])
	assert.Equal(t, "PersistentVolume", pv["kind"])
	assert.Equal(t, map[string]interface{}{"name": "data-pv"}, pv["metadata"])
	pvSpec := pv["spec"].(map[string]interface{})
	assert.Equal(t, "Retain", pvSpec["persistentVolumeReclaimPolicy"])
	assert.Equal(t, []interface{}{"ReadWriteMany"}, pvSpec["accessModes"])
	assert.Equal(t, map[string]interface{}{"path": "/export", "server": "nfs.internal"}, pvSpec["nfs"])
	assert.NotContains(t, pvSpec, "persistentVolumeSource")

	// PV node_affinity node_selector_term encodes as nodeSelectorTerms array
	nodeAffinity := pvSpec["nodeAffinity"].(map[string]interface{})
	requiredAffinity := nodeAffinity["required"].(map[string]interface{})
	nodeSelectorTerms := requiredAffinity["nodeSelectorTerms"].([]interface{})
	require.Len(t, nodeSelectorTerms, 1)
	term0 := nodeSelectorTerms[0].(map[string]interface{})
	matchExprs := term0["matchExpressions"].([]interface{})
	require.Len(t, matchExprs, 1)
	expr0 := matchExprs[0].(map[string]interface{})
	assert.Equal(t, "topology.kubernetes.io/zone", expr0["key"])
	assert.Equal(t, "In", expr0["operator"])
	assert.Equal(t, []interface{}{"us-east-1a"}, expr0["values"])

	// PV v1: cluster-scoped, azure_disk with diskURI
	pvV1 := manifests[3]
	assert.Equal(t, "v1", pvV1["apiVersion"])
	assert.Equal(t, "PersistentVolume", pvV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "log-pv"}, pvV1["metadata"])
	pvV1Spec := pvV1["spec"].(map[string]interface{})
	azureDisk := pvV1Spec["azureDisk"].(map[string]interface{})
	assert.Equal(t, "https://example.blob.core.windows.net/vhds/disk.vhd", azureDisk["diskURI"])
	assert.Equal(t, "disk.vhd", azureDisk["diskName"])

	// PDB: namespaced, numeric minAvailable string converts to json.Number
	pdb := manifests[4]
	assert.Equal(t, "policy/v1", pdb["apiVersion"])
	assert.Equal(t, "PodDisruptionBudget", pdb["kind"])
	assert.Equal(t, map[string]interface{}{"name": "api-pdb", "namespace": "default"}, pdb["metadata"])
	pdbSpec := pdb["spec"].(map[string]interface{})
	assert.Equal(t, json.Number("1"), pdbSpec["minAvailable"])

	// PDB v1: percentage maxUnavailable preserved as string
	pdbV1 := manifests[5]
	assert.Equal(t, "policy/v1", pdbV1["apiVersion"])
	assert.Equal(t, "PodDisruptionBudget", pdbV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "worker-pdb", "namespace": "workers"}, pdbV1["metadata"])
	pdbV1Spec := pdbV1["spec"].(map[string]interface{})
	assert.Equal(t, "30%", pdbV1Spec["maxUnavailable"])

	// ResourceQuota: namespaced, scope_selector.match_expression -> matchExpressions array
	quota := manifests[6]
	assert.Equal(t, "v1", quota["apiVersion"])
	assert.Equal(t, "ResourceQuota", quota["kind"])
	assert.Equal(t, map[string]interface{}{"name": "compute-quota", "namespace": "default"}, quota["metadata"])
	quotaSpec := quota["spec"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"pods": "20"}, quotaSpec["hard"])
	scopeSel := quotaSpec["scopeSelector"].(map[string]interface{})
	quotaMatchExprs := scopeSel["matchExpressions"].([]interface{})
	require.Len(t, quotaMatchExprs, 1)

	// ResourceQuota v1
	quotaV1 := manifests[7]
	assert.Equal(t, "v1", quotaV1["apiVersion"])
	assert.Equal(t, "ResourceQuota", quotaV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "mem-quota", "namespace": "apps"}, quotaV1["metadata"])

	// LimitRange: namespaced, limit block becomes limits array, default_request -> defaultRequest
	limits := manifests[8]
	assert.Equal(t, "v1", limits["apiVersion"])
	assert.Equal(t, "LimitRange", limits["kind"])
	assert.Equal(t, map[string]interface{}{"name": "core-limits", "namespace": "default"}, limits["metadata"])
	limitsSpec := limits["spec"].(map[string]interface{})
	limitsArr := limitsSpec["limits"].([]interface{})
	require.Len(t, limitsArr, 1)
	l0 := limitsArr[0].(map[string]interface{})
	assert.Equal(t, "Container", l0["type"])
	assert.Equal(t, map[string]interface{}{"cpu": "100m"}, l0["defaultRequest"])

	// LimitRange v1
	limitsV1 := manifests[9]
	assert.Equal(t, "v1", limitsV1["apiVersion"])
	assert.Equal(t, "LimitRange", limitsV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "pod-limits", "namespace": "dev"}, limitsV1["metadata"])

	// HPA: target_cpu_utilization_percentage -> targetCPUUtilizationPercentage
	hpa := manifests[10]
	assert.Equal(t, "autoscaling/v1", hpa["apiVersion"])
	assert.Equal(t, "HorizontalPodAutoscaler", hpa["kind"])
	assert.Equal(t, map[string]interface{}{"name": "web-hpa", "namespace": "default"}, hpa["metadata"])
	hpaSpec := hpa["spec"].(map[string]interface{})
	assert.Equal(t, json.Number("80"), hpaSpec["targetCPUUtilizationPercentage"])

	// HPA v1
	hpaV1 := manifests[11]
	assert.Equal(t, "autoscaling/v1", hpaV1["apiVersion"])
	assert.Equal(t, "HorizontalPodAutoscaler", hpaV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "api-hpa", "namespace": "api"}, hpaV1["metadata"])

	// HPA v2: metric block -> metrics array, policy block -> policies array
	hpaV2 := manifests[12]
	assert.Equal(t, "autoscaling/v2", hpaV2["apiVersion"])
	assert.Equal(t, "HorizontalPodAutoscaler", hpaV2["kind"])
	assert.Equal(t, map[string]interface{}{"name": "v2-hpa", "namespace": "default"}, hpaV2["metadata"])
	hpaV2Spec := hpaV2["spec"].(map[string]interface{})
	assert.Equal(t, json.Number("2"), hpaV2Spec["minReplicas"])
	metricsArr := hpaV2Spec["metrics"].([]interface{})
	require.Len(t, metricsArr, 2)
	extMetric := metricsArr[1].(map[string]interface{})
	assert.Equal(t, "External", extMetric["type"])
	extBlock := extMetric["external"].(map[string]interface{})
	metricIdent := extBlock["metric"].(map[string]interface{})
	assert.Equal(t, "queue_messages", metricIdent["name"])
	assert.NotContains(t, extBlock, "metrics")
	behavior := hpaV2Spec["behavior"].(map[string]interface{})
	scaleUp := behavior["scaleUp"].(map[string]interface{})
	policies := scaleUp["policies"].([]interface{})
	require.Len(t, policies, 1)

	// HPA v2beta2
	hpaV2beta2 := manifests[13]
	assert.Equal(t, "autoscaling/v2beta2", hpaV2beta2["apiVersion"])
	assert.Equal(t, "HorizontalPodAutoscaler", hpaV2beta2["kind"])

	// PriorityClass: cluster-scoped, NO namespace in metadata
	pc := manifests[14]
	assert.Equal(t, "scheduling.k8s.io/v1", pc["apiVersion"])
	assert.Equal(t, "PriorityClass", pc["kind"])
	assert.Equal(t, map[string]interface{}{"name": "high-priority"}, pc["metadata"])
	assert.Equal(t, json.Number("1000000"), pc["value"])
	assert.Equal(t, true, pc["globalDefault"])

	// PriorityClass v1: cluster-scoped
	pcV1 := manifests[15]
	assert.Equal(t, "scheduling.k8s.io/v1", pcV1["apiVersion"])
	assert.Equal(t, "PriorityClass", pcV1["kind"])
	assert.Equal(t, map[string]interface{}{"name": "critical-priority"}, pcV1["metadata"])
	assert.Equal(t, json.Number("2000000"), pcV1["value"])
}
