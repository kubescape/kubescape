package cautils

import (
	"encoding/json"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{"initialism as first word stays lowercase", "ip_families", "ipFamilies"},
		{"word containing an initialism is not changed", "pid_limit", "pidLimit"},
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
		"metadata": map[string]interface{}{"name": "app"},
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
	assert.Equal(t, map[string]interface{}{"name": "custom-name"}, manifests[1]["metadata"], "explicit metadata.name must be preserved")

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
	assert.Equal(t, map[string]interface{}{"name": "backup"}, manifests[1]["metadata"])

	assert.Equal(t, "networking.k8s.io/v1beta1", manifests[2]["apiVersion"])
	assert.Equal(t, "Ingress", manifests[2]["kind"])
	assert.Equal(t, map[string]interface{}{"name": "web-ingress"}, manifests[2]["metadata"])

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
	assert.Equal(t, map[string]interface{}{"name": "allow-dns"}, manifests[4]["metadata"])

	for i, m := range manifests {
		data, err := json.Marshal(m)
		require.NoError(t, err, "manifest %d must marshal cleanly to valid JSON without error", i)
		assert.NotEmpty(t, data)
	}
}
